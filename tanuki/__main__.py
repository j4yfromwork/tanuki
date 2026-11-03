"""Allow ``python -m tanuki`` to run the CLI."""
import sys

from tanuki import main

if __name__ == "__main__":
    sys.exit(main())
