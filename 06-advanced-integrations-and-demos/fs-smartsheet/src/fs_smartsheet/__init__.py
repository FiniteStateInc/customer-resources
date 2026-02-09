"""Finite State to Smartsheet integration layer."""

import warnings

# Suppress DeprecationWarnings from the Smartsheet SDK only (not all libraries)
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"smartsheet\b")

__version__ = "0.1.0"
