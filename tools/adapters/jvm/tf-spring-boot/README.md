# tf-spring-boot

Spring Boot 3.x auto-configuration for TrustForge.

- `TrustForgeFilter` runs on every request and asks `tf-daemon`.
- `@TrustForgeRequire("action")` enforces method-level checks via an AspectJ aspect.
- `application.yaml` keys: `trustforge.daemon-url`, `trustforge.filter-enabled`.

Add the dependency, then:

```java
@TrustForgeRequire("file:read")
@GetMapping("/files/{id}")
String read(...) { ... }
```
