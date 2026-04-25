package dev.trustforge.play

import dev.trustforge.{Client, TrustForgeException}
import org.junit.jupiter.api.Assertions._
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.{mock, when}
import play.api.test.FakeRequest

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import scala.concurrent.duration._

class TrustForgePlayTest {

  @Test
  def allow_returns_none(): Unit = {
    val c = mock(classOf[Client])
    when(c.decide(any[Client.Request]())).thenReturn(new Client.Decision(true, "ok", null))
    val filter = new TrustForgeFilter(c)(null, global)
    val out = Await.result(filter.filter(FakeRequest("GET", "/x")), 1.second)
    assertTrue(out.isEmpty)
  }

  @Test
  def deny_returns_403(): Unit = {
    val c = mock(classOf[Client])
    when(c.decide(any[Client.Request]())).thenReturn(new Client.Decision(false, "no", null))
    val filter = new TrustForgeFilter(c)(null, global)
    val out = Await.result(filter.filter(FakeRequest("GET", "/x")), 1.second)
    assertTrue(out.isDefined)
    assertEquals(403, out.get.header.status)
  }

  @Test
  def daemon_failure_returns_503(): Unit = {
    val c = mock(classOf[Client])
    when(c.decide(any[Client.Request]())).thenThrow(new TrustForgeException("nope"))
    val filter = new TrustForgeFilter(c)(null, global)
    val out = Await.result(filter.filter(FakeRequest("GET", "/x")), 1.second)
    assertTrue(out.isDefined)
    assertEquals(503, out.get.header.status)
  }
}
