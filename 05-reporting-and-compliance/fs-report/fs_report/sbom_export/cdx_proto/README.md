Vendored verbatim from https://github.com/CycloneDX/specification (`schema/`):

- `bom-1.6.proto` at tag 1.6.2 (e833d732337dd33aceb45ff1991f896796f1e5e7)
- `bom-1.7.proto` at tag 1.7.2 (349314a9d7671d7d2ca5b711a725f49a73979da6)

The upstream files carry no licence header; the specification repo is Apache-2.0.

Generated with grpcio-tools 1.84.0 (protobuf runtime 7.36.2). protoc turns the
`.` in `bom-1.6.proto` into a path separator, so generate one file at a time
and rename the output:

    for v in 1.6 1.7; do
      poetry run python -m grpc_tools.protoc -I . --python_out=. bom-$v.proto
      mv bom_1/${v#1.}_pb2.py bom_1_${v#1.}_pb2.py
    done
    rmdir bom_1

Packages are `cyclonedx.v1_6` / `cyclonedx.v1_7`, so both load in one process.
Generated `*_pb2.py` are excluded from black, ruff and mypy in pyproject.toml.
