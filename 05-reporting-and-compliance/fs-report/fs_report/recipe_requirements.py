# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Shared per-recipe requirement predicate.

Provides a single source of truth for whether a given Recipe effectively
requires ``--project``, ``--project-or-folder``, or ``--cve`` at dispatch.

Both the engine dispatch path (``ReportEngine._process_compound`` and the
standalone loop in ``run()``) and the web prerun computation (PR2.3) import
from here so the modal can never diverge from what dispatch enforces.

Import safety
-------------
This module depends only on :mod:`fs_report.models` (``Recipe``,
``CompoundRecipe``) and the standard library.  It MUST NOT import
``fs_report.report_engine`` or any ``fs_report.web`` module to avoid
circular imports.

Name-based rules (Decision 7)
------------------------------
Some recipes effectively require a scope filter even though they declare no
``requires_*`` flag.  The canonical example is **"Remediation Package"**:
its standalone dispatch path in ``ReportEngine.run()`` either fans out over
folder projects or raises an error if neither ``--project`` nor ``--folder``
is set.  That implicit constraint must surface in the predicate so:

* ``_process_compound`` enforces it for compound children (closing the gap
  where a Remediation Package child under no scope was not pre-checked), and
* the web prerun computation (PR2.3) can reflect it in the UI without
  re-implementing the logic.

Compound helpers (PR2.3a)
--------------------------
Plain compound recipes declare NO requirement flags of their own, but at
dispatch the engine enforces the UNION of the children's requirements.
``compound_child_names`` and ``compound_effective_requirements`` expose that
union to the web prerun path so the form can never diverge from dispatch.

Origin: Builder compound+comparison spec, Decision 7 — "name-based rules
(e.g. Remediation Package needs a project/folder despite declaring neither
flag)".
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from fs_report.models import CompoundRecipe, Recipe

# ---------------------------------------------------------------------------
# Name-based requirement rules.
# Recipes in this set effectively require --project or --folder even though
# their Recipe model declares requires_project_or_folder=False.
# Decision 7: "Remediation Package needs a project/folder despite declaring
# neither flag" — mirroring the standalone dispatch path in ReportEngine.run().
# ---------------------------------------------------------------------------
_NAME_REQUIRES_PROJECT_OR_FOLDER: frozenset[str] = frozenset({"Remediation Package"})


@dataclass(frozen=True)
class RecipeRequirements:
    """Effective scope/filter requirements for a single recipe.

    Attributes
    ----------
    requires_project:
        The recipe cannot run without ``--project``.
    requires_project_or_folder:
        The recipe cannot run without ``--project`` or ``--folder``.
        Combines the declared ``requires_project_or_folder`` flag with the
        name-based rules in :data:`_NAME_REQUIRES_PROJECT_OR_FOLDER`.
    requires_cve:
        The recipe cannot run without ``--cve``.
    requires_component:
        The recipe cannot run without ``--component`` (B4 #25).
    """

    requires_project: bool
    requires_project_or_folder: bool
    requires_cve: bool
    requires_component: bool


def recipe_requirements(recipe: Recipe) -> RecipeRequirements:
    """Return the effective dispatch requirements for *recipe*.

    Merges the declared ``requires_*`` flags with name-based rules so there
    is one authoritative answer for both engine dispatch and web prerun.

    Parameters
    ----------
    recipe:
        A :class:`~fs_report.models.Recipe` (or ``CompoundRecipe``) instance.

    Returns
    -------
    RecipeRequirements
        Frozen dataclass with the three boolean requirement fields.
    """
    return RecipeRequirements(
        requires_project=recipe.requires_project,
        requires_project_or_folder=(
            recipe.requires_project_or_folder
            or recipe.name in _NAME_REQUIRES_PROJECT_OR_FOLDER
        ),
        requires_cve=recipe.requires_cve,
        requires_component=getattr(recipe, "requires_component", False),
    )


# ---------------------------------------------------------------------------
# Compound helpers (PR2.3a)
# ---------------------------------------------------------------------------


def compound_child_names(compound: CompoundRecipe) -> list[str]:
    """Return the child recipe names for a plain (non-axis) compound.

    Only meaningful for plain compounds (``compound.axis is None``); axis
    compounds (meta-compare bundles) are out of scope for PR2.3a.

    Parameters
    ----------
    compound:
        A :class:`~fs_report.models.CompoundRecipe` instance.

    Returns
    -------
    list[str]
        Ordered list of child recipe name strings from ``sections``.
    """
    return [s.recipe for s in compound.sections]


def compound_effective_requirements(
    children: Iterable[Recipe | None],
) -> RecipeRequirements:
    """Return the OR-union of :func:`recipe_requirements` across *children*.

    A plain compound's effective dispatch requirements are the union of each
    child's requirements — if ANY child requires CVE / project / folder, the
    compound as a whole requires it.  This mirrors the enforcement in
    ``ReportEngine._process_compound``.

    Degrades gracefully: ``None`` entries (representing unresolvable child
    names) are skipped so a broken child name doesn't crash the prerun form.

    Parameters
    ----------
    children:
        An iterable of resolved :class:`~fs_report.models.Recipe` objects, or
        ``None`` for each child that could not be resolved.  ``None`` values
        are skipped.

    Returns
    -------
    RecipeRequirements
        Frozen dataclass representing the OR-union of all child requirements.
        All fields are ``False`` when *children* is empty (no constraints).
    """
    req_project = False
    req_pof = False
    req_cve = False
    req_component = False
    for child in children:
        if child is None:
            continue
        reqs = recipe_requirements(child)
        req_project = req_project or reqs.requires_project
        req_pof = req_pof or reqs.requires_project_or_folder
        req_cve = req_cve or reqs.requires_cve
        req_component = req_component or reqs.requires_component
    return RecipeRequirements(
        requires_project=req_project,
        requires_project_or_folder=req_pof,
        requires_cve=req_cve,
        requires_component=req_component,
    )


# ---------------------------------------------------------------------------
# Compound prerun input helper (PR3.0)
# ---------------------------------------------------------------------------


def compound_prerun_inputs(
    recipe: Recipe,
    resolve_child: Callable[[str], Recipe | None],
) -> tuple[RecipeRequirements, list[str]] | None:
    """For a PLAIN compound, return its (effective_requirements, child_names).

    A plain compound is a :class:`~fs_report.models.CompoundRecipe` whose
    ``axis`` attribute is ``None``.  For such a recipe the effective dispatch
    requirements are the OR-union of all children's requirements, and the
    child names are needed by ``compute_prerun_fields`` to expand the compound
    entry in the prerun grid.

    Returns ``None`` for anything that is NOT a plain compound — i.e. a plain
    (non-compound) recipe, or an axis-bearing compound/comparison recipe.
    Callers keep their existing non-compound handling for the ``None`` case.

    Parameters
    ----------
    recipe:
        A :class:`~fs_report.models.Recipe` (or ``CompoundRecipe``) instance.
    resolve_child:
        A callable that accepts a child recipe name string and returns the
        resolved :class:`~fs_report.models.Recipe` object, or ``None`` if the
        child cannot be resolved.  Unresolved children are passed as ``None``
        to :func:`compound_effective_requirements` and are silently skipped
        there.

    Returns
    -------
    tuple[RecipeRequirements, list[str]] or None
        ``(effective_requirements, child_names)`` for a plain compound, where
        *child_names* is the ordered list of child recipe name strings from
        the compound's ``sections``.  Returns ``None`` for non-plain-compound
        inputs.

    Import safety
    -------------
    This helper depends only on :mod:`fs_report.models` and sibling functions
    in this module.  It MUST NOT import ``fs_report.report_engine`` or any
    ``fs_report.web`` module.
    """
    if not (isinstance(recipe, CompoundRecipe) and recipe.axis is None):
        return None

    child_names = compound_child_names(recipe)
    resolved_children = [resolve_child(name) for name in child_names]
    effective = compound_effective_requirements(resolved_children)
    return effective, child_names
