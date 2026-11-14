"""``python -m sshdguard`` runs the same CLI as the ``sshdguard`` entry point."""

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
