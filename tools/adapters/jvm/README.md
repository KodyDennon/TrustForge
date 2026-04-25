# TrustForge JVM Adapters (Phase H)

Maven multi-module suite of JVM-side adapters that delegate authorization
decisions to a local `tf-daemon` over its `/v1/decide` HTTP endpoint.

## Modules

| Module | Framework | Language |
| --- | --- | --- |
| `tf-jvm-client` | shared HTTP client | Java 17 |
| `tf-spring-boot` | Spring Boot 3.x | Java 17 |
| `tf-micronaut` | Micronaut 4.x | Java 17 |
| `tf-quarkus` | Quarkus 3.x | Java 17 |
| `tf-vertx` | Vert.x 4.x | Java 17 |
| `tf-ktor` | Ktor (Netty) | Kotlin 1.9 |
| `tf-play` | Play Framework 2.9 | Scala 2.13 |
| `tf-spark-java` | SparkJava | Java 17 |
| `tf-helidon` | Helidon SE 4 | Java 17 |

## Build

Requires **JDK 17** and **Maven 3.9+**.

```bash
mvn -f tools/adapters/jvm/pom.xml verify
```

If `mvn` is not installed:

- macOS: `brew install maven openjdk@17`
- Debian/Ubuntu: `apt-get install maven openjdk-17-jdk`
- Manual: https://maven.apache.org/install.html and https://adoptium.net/

## Status

Draft (Phase H). Not production-ready. All adapters call the local
`tf-daemon` rather than implementing authorization themselves; that
isolation is intentional and required.
