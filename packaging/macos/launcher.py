"""PyInstaller entry point for the LogSalvo macOS application bundle."""

from logsalvo.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
