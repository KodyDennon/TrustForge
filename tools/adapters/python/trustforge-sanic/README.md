# trustforge-sanic

Sanic middleware that authorises every HTTP request against the TrustForge
`tf-daemon` `/v1/decide` endpoint.

The middleware attaches the resolved `DecideResponse` to `request.ctx.tf_decision`
on `allow`. On `deny` it returns 403 JSON; on `approval_required` it returns 202
JSON. When the daemon is unreachable and `mode="observe-only"` it forwards
through unmodified, otherwise it returns 503.

```python
from sanic import Sanic
from trustforge_sanic import attach_trustforge

app = Sanic("demo")
attach_trustforge(
    app,
    daemon_url="http://127.0.0.1:8787",
    default_action="http.request",
)
```
