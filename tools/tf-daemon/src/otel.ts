/**
 * tf-daemon OpenTelemetry tracing wiring.
 *
 * The daemon emits one span per `/v1/decide` request. Spans carry the
 * standard TrustForge decide attributes:
 *   - `tf.action`         the requested action (e.g. `fs.write`)
 *   - `tf.target`         the target URI/path/null
 *   - `tf.decision`       the resolved decision kind (allow|deny|...)
 *   - `tf.actor_resolved` the post-resolution actor URI
 *
 * Initialization is opt-in. The SDK is brought up only when
 * `OTEL_EXPORTER_OTLP_ENDPOINT` is set (or `otlpEndpoint` is passed). In
 * production this delegates to `@opentelemetry/sdk-node` and exports OTLP
 * over gRPC. For tests we expose `setOtelTestExporter` so a synchronous
 * in-memory exporter can be installed without a live OTLP receiver — that
 * is the idiomatic way to assert span shape in unit tests.
 *
 * Both the SDK path and the test path go through `recordDecideSpan` so the
 * daemon never branches on "are we under test?" in the hot path.
 */

export interface DecideSpanAttributes {
  "tf.action": string;
  "tf.target": string;
  "tf.decision": string;
  "tf.actor_resolved": string;
}

export interface RecordedSpan {
  name: string;
  attributes: DecideSpanAttributes;
  startedAt: number;
  endedAt: number;
}

export interface OtelHandle {
  /** Service name advertised on every span. */
  serviceName: string;
  /** Configured OTLP gRPC endpoint, or null if running in test/dev mode
   *  without the SDK. */
  otlpEndpoint: string | null;
  /** Force-flush any buffered spans (best effort). */
  flush(): Promise<void>;
  /** Tear down the SDK if it was initialized. */
  shutdown(): Promise<void>;
}

type TestExporter = (span: RecordedSpan) => void;
let testExporter: TestExporter | null = null;
let otelEnabled = false;
let otelServiceName = "tf-daemon";
let sdkInstance: { shutdown: () => Promise<void> } | null = null;
let tracerInstance: unknown = null;

/**
 * Install an in-memory exporter for tests. Returns a teardown function.
 * Each emitted span (decide or otherwise) is delivered synchronously to
 * the supplied callback, regardless of whether the SDK was initialized.
 */
export function setOtelTestExporter(exporter: TestExporter | null): void {
  testExporter = exporter;
}

/**
 * Initialize the OpenTelemetry SDK if `OTEL_EXPORTER_OTLP_ENDPOINT` is
 * set (or `otlpEndpoint` is supplied). Safe to call multiple times — the
 * second call is a no-op unless the first was torn down via `shutdown()`.
 *
 * Returns a handle the caller can hold to flush/shutdown. The handle is
 * safe to discard; the daemon's process exit will not block on OTel.
 */
export async function setupOtel(
  serviceName: string,
  otlpEndpoint?: string,
): Promise<OtelHandle> {
  otelServiceName = serviceName;
  const endpoint = otlpEndpoint ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? null;

  if (!endpoint) {
    // No endpoint and no test exporter installed → tracing is silently
    // off. recordDecideSpan still no-ops correctly in that mode.
    otelEnabled = !!testExporter;
    return {
      serviceName,
      otlpEndpoint: null,
      flush: async () => {
        /* no-op */
      },
      shutdown: async () => {
        otelEnabled = false;
      },
    };
  }

  // Endpoint is set → bring up the SDK. We import lazily so an operator
  // who hasn't installed the OTel packages can still run the daemon as
  // long as they don't request OTLP.
  try {
    const sdkMod = (await import("@opentelemetry/sdk-node")) as unknown as {
      NodeSDK: new (cfg: unknown) => { start: () => void; shutdown: () => Promise<void> };
    };
    const otlpMod = (await import("@opentelemetry/exporter-trace-otlp-grpc")) as unknown as {
      OTLPTraceExporter: new (cfg: unknown) => unknown;
    };
    const httpMod = (await import("@opentelemetry/instrumentation-http")) as unknown as {
      HttpInstrumentation: new () => unknown;
    };
    const apiMod = (await import("@opentelemetry/api")) as unknown as {
      trace: { getTracer(name: string): unknown };
    };

    const traceExporter = new otlpMod.OTLPTraceExporter({ url: endpoint });
    const sdk = new sdkMod.NodeSDK({
      serviceName,
      traceExporter,
      instrumentations: [new httpMod.HttpInstrumentation()],
    });
    sdk.start();
    sdkInstance = sdk;
    tracerInstance = apiMod.trace.getTracer("tf-daemon");
    otelEnabled = true;
  } catch (err) {
    // The OTel packages aren't installed — operator turned on the
    // environment but didn't supply the SDK. Surface a one-shot warning
    // and fall back to the test-exporter path (which may also be absent,
    // in which case spans are silently dropped).
    // eslint-disable-next-line no-console
    console.warn(
      `[tf-daemon] OTel SDK requested (endpoint=${endpoint}) but @opentelemetry/sdk-node is not installed: ${(err as Error).message}`,
    );
    otelEnabled = !!testExporter;
  }

  return {
    serviceName,
    otlpEndpoint: endpoint,
    flush: async () => {
      // sdk-node has no public flush; the OTLP exporter buffers. Best
      // effort: a tiny delay lets the batcher drain.
      if (sdkInstance) await new Promise((r) => setTimeout(r, 50));
    },
    shutdown: async () => {
      if (sdkInstance) {
        try {
          await sdkInstance.shutdown();
        } catch {
          /* tolerate shutdown errors */
        }
      }
      sdkInstance = null;
      tracerInstance = null;
      otelEnabled = !!testExporter;
    },
  };
}

/**
 * Record a span for one `/v1/decide` request. The span name is
 * `tf.decide` and carries the four standard attributes plus the daemon's
 * service name.
 *
 * The function is fire-and-forget: it never throws and never awaits
 * exporter I/O on the request path.
 */
export function recordDecideSpan(attrs: DecideSpanAttributes): void {
  const startedAt = Date.now();
  // Test-exporter path: delivers synchronously so unit tests don't have
  // to await a batcher.
  if (testExporter) {
    try {
      testExporter({
        name: "tf.decide",
        attributes: { ...attrs },
        startedAt,
        endedAt: startedAt,
      });
    } catch {
      /* tolerate exporter errors in tests */
    }
  }
  if (!otelEnabled || !tracerInstance) return;
  try {
    const tracer = tracerInstance as {
      startSpan(name: string, opts?: { attributes?: Record<string, unknown> }): {
        setAttribute(k: string, v: unknown): void;
        end(): void;
      };
    };
    const span = tracer.startSpan("tf.decide", {
      attributes: {
        "service.name": otelServiceName,
        "tf.action": attrs["tf.action"],
        "tf.target": attrs["tf.target"],
        "tf.decision": attrs["tf.decision"],
        "tf.actor_resolved": attrs["tf.actor_resolved"],
      },
    });
    span.end();
  } catch {
    /* never break a decide on a tracing failure */
  }
}

/** Returns true iff OTel is currently emitting spans (either the SDK is
 *  up OR a test exporter is installed). Used by tests to assert wire-up
 *  without poking at internals. */
export function isOtelActive(): boolean {
  return otelEnabled || testExporter !== null;
}
