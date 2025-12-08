"""
Finite State Reporter - Generate professional PDF reports from Finite State API data.

This package provides tools to create comprehensive risk summary reports
with professional styling and detailed findings analysis.
"""

__version__ = "1.0.0"
__author__ = "Finite State"
__email__ = "support@finitestate.io"

from .cli import cli
from .core.reporter import FiniteStateReporter, main

__all__ = ["FiniteStateReporter", "main", "cli"]
