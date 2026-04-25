# tf-helidon

Helidon SE 4 WebServer middleware:

```java
WebServer.builder()
    .routing(r -> r.register("/", TrustForgeService.create("http://127.0.0.1:7878"))
                   .get("/hello", (req, res) -> res.send("hi")))
    .start();
```
