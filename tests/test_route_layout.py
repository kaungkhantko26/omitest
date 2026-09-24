import ast
from pathlib import Path


def _api_routes():
    tree = ast.parse(Path("main.py").read_text(encoding="utf-8"))
    routes = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            func = decorator.func
            if not (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "app"
                and func.attr in {"get", "post", "put", "patch", "delete"}
            ):
                continue
            path = decorator.args[0]
            if isinstance(path, ast.Constant) and isinstance(path.value, str):
                routes.append((func.attr.upper(), path.value, node.name))
    return routes


def test_api_routes_are_unique():
    routes = _api_routes()
    identities = [(method, path) for method, path, _ in routes]
    assert len(identities) == len(set(identities))


def test_session_history_does_not_collide_with_session_id_route():
    paths = {path for _, path, _ in _api_routes()}
    assert "/api/session-history" in paths
    assert "/api/sessions/history" not in paths
