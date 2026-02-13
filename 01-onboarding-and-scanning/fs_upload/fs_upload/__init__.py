"""Finite State Upload Package"""
# Import main function from the script
import sys
from pathlib import Path

# Add parent directory to path to import from fs-upload.py
script_dir = Path(__file__).parent.parent
sys.path.insert(0, str(script_dir))

# Import main from the script module
# We need to import it as a module, so we'll use importlib
import importlib.util
spec = importlib.util.spec_from_file_location("fs_upload_script", script_dir / "fs-upload.py")
if spec and spec.loader:
    fs_upload_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fs_upload_module)
    main = fs_upload_module.main
else:
    def main():
        print("Error: Could not load fs-upload.py")
        sys.exit(1)

__all__ = ['main']

