# trustforge-tornado

Tornado `RequestHandler` decorator that authorises every method through
`tf-daemon /v1/decide`.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-tornado
```

## Usage

```python
import tornado.web
from trustforge_tornado import TrustForge

tf = TrustForge(daemon_url="http://127.0.0.1:7616", admin_token="dev")

class FilesHandler(tornado.web.RequestHandler):
    @tf.require("file.read")
    async def get(self, path):
        self.write({"path": path})
```

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
