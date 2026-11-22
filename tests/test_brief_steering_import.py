"""The brief's dead-looking-code lines come from decompnet.steering: briefs.py (in app/engine) imported it as
`from .. import steering`, which is decompnet.app, so every get_function brief raised ImportError."""
import ast
from pathlib import Path

import decompnet
from decompnet.app.engine import briefs


def test_relative_imports_in_briefs_resolve():
    tree = ast.parse(Path(briefs.__file__).read_text(encoding="utf-8"))
    base = briefs.__name__.split(".")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and node.module is None:
            package = ".".join(base[:len(base) - node.level])
            for alias in node.names:
                module = f"{package}.{alias.name}"
                path = Path(decompnet.__file__).parents[1].joinpath(*module.split("."))
                assert path.with_suffix(".py").is_file() or (path / "__init__.py").is_file(), (
                    f"briefs.py imports {module}, which doesn't exist")
