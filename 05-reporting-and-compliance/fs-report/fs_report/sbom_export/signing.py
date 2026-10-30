"""SBOM signing: cosign detached bundles, embedded JSF (CycloneDX JSON) and
XML-DSig (CycloneDX XML).

Key passwords come only from the ``COSIGN_PASSWORD`` environment variable and
are never placed in argv or logs.
"""

from __future__ import annotations

import base64
import copy
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from lxml import etree  # type: ignore[import-untyped]
from signxml import CanonicalizationMethod, SignatureMethod, XMLSigner

REKOR_WARNING = (
    "Keyless signing records this SBOM's signature and your identity in the "
    "public Sigstore Rekor transparency log."
)
_COSIGN_MISSING = (
    "cosign not found on PATH — install from "
    "https://docs.sigstore.dev/cosign/system_config/installation/"
)
# cosign 3.x: key mode must not upload to the public Rekor log, and must not
# fetch the TUF signing config (which would re-enable Rekor). Both flags are
# deprecated-but-supported in 3.x and together keep key signing fully offline;
# --use-signing-config first shipped in cosign 2.6.0.
_NO_TLOG = ["--tlog-upload=false", "--use-signing-config=false"]
_TIMEOUT_S = 300


class SigningError(RuntimeError):
    """Raised when an SBOM cannot be signed."""


def cosign_sign(
    path: Path,
    *,
    key: str | None,
    keyless: bool,
    identity_token: str | None,
    logger: logging.Logger,
) -> list[Path]:
    """Write a detached Sigstore bundle ``{path}.bundle``; return ``[bundle]``.

    Non-interactive modes (key, or keyless with a token) get no stdin, so a
    missing password fails fast instead of prompting on hidden stderr. Keyless
    without a token runs cosign's browser/device login flow on the user's
    terminal (stderr not captured) with no timeout.
    """
    if shutil.which("cosign") is None:
        raise SigningError(_COSIGN_MISSING)
    if bool(key) == keyless:
        raise SigningError("cosign signing needs exactly one of key or keyless")
    bundle = path.with_name(path.name + ".bundle")
    env = os.environ.copy()  # inherits COSIGN_PASSWORD
    argv = ["cosign", "sign-blob", "--yes"]
    if keyless:
        logger.warning(REKOR_WARNING)
        if identity_token:
            env["SIGSTORE_ID_TOKEN"] = identity_token  # kept out of argv
    else:
        argv += ["--key", str(key), *_NO_TLOG]
    argv += ["--bundle", str(bundle), str(path)]
    interactive = keyless and not identity_token
    secrets = [t for t in (identity_token, env.get("SIGSTORE_ID_TOKEN")) if t]
    try:
        if interactive:
            r = subprocess.run(argv, env=env, text=True, check=False)
        else:
            r = subprocess.run(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=_TIMEOUT_S,
            )
    except subprocess.TimeoutExpired as e:
        logger.error("cosign sign-blob timed out after %ss", _TIMEOUT_S)
        raise SigningError(f"cosign sign-blob timed out after {_TIMEOUT_S}s") from e
    if r.returncode != 0:
        err = (r.stderr or "").strip()
        for t in secrets:
            err = err.replace(t, "***")
        if not keyless and "reading key" in err:
            err += (
                "\nHint: set COSIGN_PASSWORD to the key's password; cosign "
                "needs a cosign-format key (cosign generate-key-pair / "
                "import-key-pair)."
            )
        if not keyless and "unknown flag: --use-signing-config" in err:
            err += "\nHint: key signing needs cosign 2.6 or later."
        logger.error("cosign sign-blob failed (exit %s)", r.returncode)
        raise SigningError(f"cosign sign-blob failed (exit {r.returncode}): {err}")
    return [bundle]


def _load_key(key_pem: Path) -> Any:
    data = key_pem.read_bytes()
    if b"SIGSTORE PRIVATE KEY" in data:
        raise SigningError(
            "embedded signing needs a standard PEM private key; cosign-format "
            "keys (from 'cosign generate-key-pair') are not supported"
        )
    pw = os.environ.get("COSIGN_PASSWORD")
    try:
        try:
            return serialization.load_pem_private_key(data, pw.encode() if pw else None)
        except TypeError:  # password set but key unencrypted (or vice versa)
            if not pw:
                raise
            return serialization.load_pem_private_key(data, None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as e:
        raise SigningError(f"cannot load private key {key_pem}: {e}") from e


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk_and_alg(key: Any) -> tuple[dict[str, str], str]:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}, "Ed25519"
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
        key.curve, ec.SECP256R1
    ):
        n = key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u(n.x.to_bytes(32, "big")),
            "y": _b64u(n.y.to_bytes(32, "big")),
        }, "ES256"
    if isinstance(key, rsa.RSAPrivateKey):
        rn = key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "n": _b64u(rn.n.to_bytes((rn.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(rn.e.to_bytes((rn.e.bit_length() + 7) // 8, "big")),
        }, "RS256"
    raise SigningError("unsupported key type; use Ed25519, EC P-256 or RSA")


def sign_jsf(cdx: dict[str, Any], key_pem: Path) -> dict[str, Any]:
    """Return a copy of ``cdx`` with an embedded JSF ``signature``.

    Signed data = JCS (RFC 8785) of the whole BOM with ``signature.value`` omitted.
    """
    key = _load_key(key_pem)
    jwk, alg = _jwk_and_alg(key)
    out = copy.deepcopy(cdx)
    out["signature"] = {"algorithm": alg, "publicKey": jwk}
    data = rfc8785.dumps(out)
    if alg == "Ed25519":
        sig = key.sign(data)
    elif alg == "ES256":
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    out["signature"]["value"] = _b64u(sig)
    return out


def verify_jsf(cdx: dict[str, Any]) -> bool:
    """Verify an embedded JSF signature against its own ``publicKey``.

    Proves integrity only; callers must check the key is one they trust.
    """
    try:
        unsigned = copy.deepcopy(cdx)
        sig_obj = unsigned["signature"]
        sig = _unb64u(sig_obj.pop("value"))
        alg, jwk = sig_obj["algorithm"], sig_obj["publicKey"]
        data = rfc8785.dumps(unsigned)
        if alg == "Ed25519" and jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(_unb64u(jwk["x"])).verify(
                sig, data
            )
        elif alg == "ES256" and jwk["kty"] == "EC" and jwk["crv"] == "P-256":
            if len(sig) != 64:
                return False
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_unb64u(jwk["x"]), "big"),
                int.from_bytes(_unb64u(jwk["y"]), "big"),
                ec.SECP256R1(),
            ).public_key()
            der = encode_dss_signature(
                int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            )
            pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
        elif alg == "RS256" and jwk["kty"] == "RSA":
            rsa.RSAPublicNumbers(
                int.from_bytes(_unb64u(jwk["e"]), "big"),
                int.from_bytes(_unb64u(jwk["n"]), "big"),
            ).public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, KeyError, TypeError, ValueError, AttributeError):
        return False
    return True


def sign_xmldsig(xml: bytes, key_pem: Path) -> bytes:
    """Enveloped XML-DSig on the root ``bom`` element (appended as last child)."""
    key = _load_key(key_pem)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        method = SignatureMethod.ECDSA_SHA256
    elif isinstance(key, rsa.RSAPrivateKey):
        method = SignatureMethod.RSA_SHA256
    else:
        raise SigningError(
            "XML-DSig supports EC or RSA keys only (Ed25519 is not supported)"
        )
    root = etree.fromstring(xml, parser=etree.XMLParser(resolve_entities=False))
    # C14N 1.0 rather than signxml's default 1.1: .NET SignedXml (used by the
    # CycloneDX CLI 'verify all') rejects the 1.1 transform.
    signed = XMLSigner(
        signature_algorithm=method,
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0,
    ).sign(root, key=key)
    out: bytes = etree.tostring(signed, xml_declaration=True, encoding="UTF-8")
    return out
