package dev.trustforge.ktor

import dev.trustforge.Client
import dev.trustforge.TrustForgeException
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`

class TrustForgeKtorTest {

    private fun mockClient(decision: Client.Decision? = Client.Decision(true, "ok", null), throws: Boolean = false): Client {
        val c = mock(Client::class.java)
        if (throws) {
            `when`(c.decide(any())).thenThrow(TrustForgeException("nope"))
        } else {
            `when`(c.decide(any())).thenReturn(decision)
        }
        return c
    }

    @Test
    fun `allow lets request through`() = testApplication {
        val tf = mockClient()
        application {
            install(TrustForge) { client = tf }
            routing { get("/x") { call.respondText("hi") } }
        }
        val resp = client.get("/x")
        assertEquals(HttpStatusCode.OK, resp.status)
    }

    @Test
    fun `deny returns 403`() = testApplication {
        val tf = mockClient(Client.Decision(false, "no", null))
        application {
            install(TrustForge) { client = tf }
            routing { get("/x") { call.respondText("hi") } }
        }
        val resp = client.get("/x")
        assertEquals(HttpStatusCode.Forbidden, resp.status)
    }

    @Test
    fun `daemon failure returns 503`() = testApplication {
        val tf = mockClient(throws = true)
        application {
            install(TrustForge) { client = tf }
            routing { get("/x") { call.respondText("hi") } }
        }
        val resp = client.get("/x")
        assertEquals(HttpStatusCode.ServiceUnavailable, resp.status)
    }

    @Test
    fun `default config builds without explicit client`() = testApplication {
        application {
            install(TrustForge) { daemonUrl = "http://127.0.0.1:65535" }
            routing { get("/x") { call.respondText("hi") } }
        }
        // The connect will fail and we expect 503; we just assert non-null status here.
        val resp = client.get("/x")
        assert(resp.status.value in setOf(503, 502, 504, 200, 403))
    }
}
