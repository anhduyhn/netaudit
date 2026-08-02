"""PyInstaller entry point - keeps the exe's startup outside the package."""
from netauditor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
