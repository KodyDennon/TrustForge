# tf-play

Play 2.9 (Scala 2.13) action filter:

```scala
class HomeController @Inject()(tf: TrustForgeFilter) extends BaseController {
  def index = tf { req => Ok("hi") }
}
```
