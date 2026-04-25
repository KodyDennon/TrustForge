# tf-jvm-client

Shared HTTP client for the local `tf-daemon`'s `POST /v1/decide` endpoint,
used by every JVM adapter in this directory.

```java
Client tf = new Client("http://127.0.0.1:7878");
Client.Decision d = tf.decide(new Client.Request()
    .actor("tf:actor:agent:example.com/x")
    .action("read")
    .resource("file:/tmp/x"));
if (!d.allow()) throw new SecurityException(d.reason());
```

Build/test: `mvn -pl tf-jvm-client -am verify` from `tools/adapters/jvm/`.
Requires JDK 17 and Maven 3.9+.
