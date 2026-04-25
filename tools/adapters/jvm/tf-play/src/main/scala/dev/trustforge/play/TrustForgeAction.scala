package dev.trustforge.play

import dev.trustforge.{Client, TrustForgeException}
import play.api.mvc._

import scala.concurrent.{ExecutionContext, Future}

/**
 * Play action filter that consults the local tf-daemon for every request.
 */
class TrustForgeFilter(client: Client)(implicit val parser: BodyParsers.Default, ec: ExecutionContext)
  extends ActionFilter[Request] with ActionBuilder[Request, AnyContent] {

  override protected def executionContext: ExecutionContext = ec

  override protected def filter[A](request: Request[A]): Future[Option[Result]] = Future {
    val r = new Client.Request()
      .action("http:" + request.method.toLowerCase)
      .resource(request.path)
    try {
      val d = client.decide(r)
      if (!d.allow()) Some(Results.Forbidden("""{"error":"trustforge_denied"}""").as("application/json"))
      else None
    } catch {
      case _: TrustForgeException =>
        Some(Results.ServiceUnavailable("""{"error":"trustforge_unavailable"}""").as("application/json"))
    }
  }

  override def invokeBlock[A](request: Request[A], block: Request[A] => Future[Result]): Future[Result] = {
    filter(request).flatMap {
      case Some(result) => Future.successful(result)
      case None         => block(request)
    }
  }
}
