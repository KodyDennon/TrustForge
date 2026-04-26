# trustforge-litestar

Litestar ASGI middleware that authorises every HTTP request against the
TrustForge `tf-daemon` `/v1/decide` endpoint.

```python
from litestar import Litestar, get
from litestar.middleware.base import DefineMiddleware
from trustforge_litestar import TrustforgeMiddleware, provide_tf_decision

app = Litestar(
    route_handlers=[...],
    middleware=[
        DefineMiddleware(
            TrustforgeMiddleware,
            daemon_url="http://127.0.0.1:8787",
            default_action="http.request",
        )
    ],
    dependencies={"tf_decision": provide_tf_decision},
)
```

`tf_decision` is available via DI on any handler that declares it as a
parameter; on `allow` it is the parsed `DecideResponse`. On `deny` the
middleware returns 403 JSON; on `approval-required` it returns 202 JSON.
