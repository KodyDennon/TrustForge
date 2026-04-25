# trustforge-starlette

ASGI middleware that authorises every Starlette request through
`tf-daemon /v1/decide`. The action name is taken from the
`x-tf-action` request header or the per-route default in `route_actions`.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-starlette
```

## Usage

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route
from trustforge_starlette import TrustForgeMiddleware

app = Starlette(
    middleware=[
        Middleware(
            TrustForgeMiddleware,
            daemon_url="http://127.0.0.1:7616",
            admin_token="dev",
            route_actions={"/files": "file.read"},
        )
    ],
    routes=[Route("/files", lambda r: ...)],
)
```

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
