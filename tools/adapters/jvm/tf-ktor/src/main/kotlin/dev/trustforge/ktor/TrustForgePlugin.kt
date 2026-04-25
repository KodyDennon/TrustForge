package dev.trustforge.ktor

import dev.trustforge.Client
import dev.trustforge.TrustForgeException
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.application.hooks.*
import io.ktor.server.response.*

class TrustForgeConfig {
    var daemonUrl: String = "http://127.0.0.1:7878"
    var client: Client? = null
}

val TrustForge = createApplicationPlugin(name = "TrustForge", createConfiguration = ::TrustForgeConfig) {
    val tf: Client = pluginConfig.client ?: Client(pluginConfig.daemonUrl)

    onCall { call ->
        val req = Client.Request()
            .action("http:" + call.request.httpMethod.value.lowercase())
            .resource(call.request.path())
        try {
            val d = tf.decide(req)
            if (!d.allow()) {
                call.respondText(
                    contentType = ContentType.Application.Json,
                    status = HttpStatusCode.Forbidden,
                    text = "{\"error\":\"trustforge_denied\"}"
                )
            }
        } catch (e: TrustForgeException) {
            call.respondText(
                contentType = ContentType.Application.Json,
                status = HttpStatusCode.ServiceUnavailable,
                text = "{\"error\":\"trustforge_unavailable\"}"
            )
        }
    }
}
