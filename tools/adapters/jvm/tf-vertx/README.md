# tf-vertx

Vert.x Web routing handler:

```java
Router router = Router.router(vertx);
router.route().handler(TrustForgeHandler.create("http://127.0.0.1:7878"));
```
