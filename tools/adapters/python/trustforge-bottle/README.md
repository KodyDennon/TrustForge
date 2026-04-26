# trustforge-bottle

Bottle plugin (api=2) that authorises every request against the TrustForge
`tf-daemon` `/v1/decide` endpoint.

```python
import bottle
from trustforge_bottle import TrustforgePlugin

app = bottle.Bottle()
app.install(TrustforgePlugin(
    daemon_url="http://127.0.0.1:8787",
    default_action="http.request",
))

@app.get("/files")
def read():
    decision = bottle.request.tf_decision
    return {"ok": True, "decision": decision.decision}
```

The plugin calls the daemon synchronously (via `asyncio.run`) since Bottle is
WSGI. On `allow` it attaches the resolved `DecideResponse` to
`bottle.request.tf_decision`; on `deny` it returns 403 JSON; on
`approval-required` it returns 202 JSON.
