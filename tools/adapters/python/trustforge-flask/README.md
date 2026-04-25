# trustforge-flask

Flask extension that adds a `@trustforge.require_cap("action")` decorator
which authorises the request through the TrustForge `tf-daemon /v1/decide`
endpoint.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-flask
```

## Usage

```python
from flask import Flask
from trustforge_flask import TrustForge

trustforge = TrustForge(daemon_url="http://127.0.0.1:7616", admin_token="dev")
app = Flask(__name__)
trustforge.init_app(app)

@app.get("/files/<path:path>")
@trustforge.require_cap("file.read")
def read_file(path):
    return {"path": path}
```

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
