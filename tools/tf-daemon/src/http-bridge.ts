import type { HttpBridgeHandler, HttpFrame } from "tf-types";

/**
 * Http-bridge handler implementation for tf-daemon.
 *
 * Proxies incoming HttpFrame streams to local HTTP servers.
 */
export const httpBridgeHandler: HttpBridgeHandler = async function* (
  initial: unknown,
  frames: AsyncIterable<HttpFrame>,
  ctx,
) {
  // initial could carry a 'target_url' hint if the plugin/config permits.
  const targetUrl = (initial as any)?.target_url ?? "http://127.0.0.1:8080";
  console.log(`[http-bridge] proxying ${ctx.callId} to ${targetUrl}`);

  const controller = new AbortController();
  const { signal } = controller;

  // We need to convert the AsyncIterable<HttpFrame> into a Request body
  // and the Response body back into an AsyncIterable<HttpFrame>.
  let requestHeaders: Record<string, string> = {};
  let method = "GET";
  let path = "/";

  const requestBody = new ReadableStream({
    async start(controller) {
      try {
        for await (const frame of frames) {
          if (frame.kind === "request-headers") {
            method = frame.method;
            path = frame.path;
            requestHeaders = frame.headers;
          } else if (frame.kind === "body-chunk") {
            controller.enqueue(Buffer.from(frame.data, "base64"));
          } else if (frame.kind === "trailers") {
            // fetch doesn't support trailers well yet
            controller.close();
            break;
          }
        }
      } catch (err) {
        controller.error(err);
      } finally {
        try { controller.close(); } catch { /* ignore */ }
      }
    }
  });

  // Note: we can't start the fetch until we have the headers.
  // The first frame MUST be request-headers.
  // This implementation is a bit naive (waits for the first frame).
  
  // Real implementation would use a more sophisticated stream splitter.
  // For v0.1.0 prototype, we'll assume the client sends headers first.

  const res = await fetch(new URL(path, targetUrl).toString(), {
    method,
    headers: requestHeaders,
    body: method === "GET" || method === "HEAD" ? undefined : requestBody,
    // @ts-ignore - Bun/Node fetch streaming
    duplex: "half",
    signal,
  });

  yield {
    kind: "response-headers",
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
  };

  if (res.body) {
    const reader = res.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        yield {
          kind: "body-chunk",
          data: Buffer.from(value).toString("base64"),
        };
      }
    } finally {
      reader.releaseLock();
    }
  }

  yield {
    kind: "trailers",
    headers: {}, // TODO
  };
};
