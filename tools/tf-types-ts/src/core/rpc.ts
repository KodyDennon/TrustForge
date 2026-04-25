/**
 * ProofRPC runtime — Phase 4 prototype.
 *
 * Sits on top of tf-session. Each RpcFrame is carried inside a
 * SessionFrame.Data payload. No additional framing or integrity — the
 * session already provides AEAD + sequence numbers.
 *
 * Capability enforcement is pluggable via CapabilityEnforcer; Phase 4
 * ships an always-allow and a deny-all default.
 */

import type { SessionFrame } from "./session.js";

export type RpcErrorCode =
  | "invalid_argument"
  | "unauthenticated"
  | "permission_denied"
  | "not_found"
  | "internal";

export interface RpcError {
  code: RpcErrorCode;
  message: string;
}

export class RpcCallError extends Error {
  readonly code: RpcErrorCode;
  constructor(err: RpcError) {
    super(`${err.code}: ${err.message}`);
    this.code = err.code;
  }
}

export type RpcFrame =
  | { kind: "rpc-call"; call_id: string; method: string; request: unknown }
  | { kind: "rpc-response"; call_id: string; status: "ok" | "error"; response?: unknown; error?: RpcError }
  | { kind: "rpc-stream"; call_id: string; seq: number; more: boolean; value?: unknown; error?: RpcError }
  /** Client → server stream message used by client-streaming, bidi, command-channel,
   *  bulk-transfer, telemetry, remote-shell, agent-session method kinds. */
  | { kind: "rpc-client-stream"; call_id: string; seq: number; more: boolean; value?: unknown; error?: RpcError };

export interface RpcProofEventStub {
  type: "rpc.call";
  method: string;
  call_id: string;
  caller: string;
  result: "ok" | "error";
  error_code?: RpcErrorCode;
}

export type CapabilityVerdict = "allow" | { deny: string };

export interface CapabilityEnforcer {
  /** May return synchronously or via a Promise. The RpcServer awaits the
   *  result so the enforcer can push to an approval queue and await a human. */
  check(caller: string, method: string, capability: string): CapabilityVerdict | Promise<CapabilityVerdict>;
}

export const allowAllEnforcer: CapabilityEnforcer = {
  check: () => "allow",
};

export const denyAllEnforcer: CapabilityEnforcer = {
  check: () => ({ deny: "capability enforcement denied all" }),
};

/** Endpoint-like contract; tf-session's SessionEndpoint already satisfies this. */
export interface RpcTransport {
  send(frame: SessionFrame): void;
  onFrame(listener: (frame: SessionFrame) => void): void;
}

// ---------- helpers ----------

function newCallId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function encodeRpc(frame: RpcFrame): SessionFrame {
  return { kind: "data", payload: frame };
}

function decodeRpc(frame: SessionFrame): RpcFrame | null {
  if (frame.kind !== "data" || !frame.payload || typeof frame.payload !== "object") return null;
  const p = frame.payload as RpcFrame;
  if (
    p.kind === "rpc-call" ||
    p.kind === "rpc-response" ||
    p.kind === "rpc-stream" ||
    p.kind === "rpc-client-stream"
  )
    return p;
  return null;
}

// ---------- client ----------

interface PendingUnary {
  kind: "unary";
  resolve: (value: unknown) => void;
  reject: (err: RpcCallError) => void;
}

interface PendingStream {
  kind: "stream";
  push: (value: unknown) => void;
  done: () => void;
  fail: (err: RpcCallError) => void;
  nextSeq: number;
}

export class RpcClient {
  private pending = new Map<string, PendingUnary | PendingStream>();

  constructor(
    private transport: RpcTransport,
    private options: { callerActor: string; onProofEvent?: (ev: RpcProofEventStub) => void } = {
      callerActor: "tf:actor:process:local/unknown",
    },
  ) {
    this.transport.onFrame((f) => this.onFrame(f));
  }

  async call<Req, Res>(method: string, request: Req): Promise<Res> {
    const call_id = newCallId();
    const frame: RpcFrame = { kind: "rpc-call", call_id, method, request };
    return new Promise<Res>((resolve, reject) => {
      this.pending.set(call_id, {
        kind: "unary",
        resolve: (v) => resolve(v as Res),
        reject,
      });
      this.transport.send(encodeRpc(frame));
    });
  }

  /** Client-streaming: client emits N requests, server returns 1 response. */
  async clientStream<Req, Res>(
    method: string,
    requests: AsyncIterable<Req>,
    initial?: Req,
  ): Promise<Res> {
    const call_id = newCallId();
    return new Promise<Res>((resolve, reject) => {
      this.pending.set(call_id, {
        kind: "unary",
        resolve: (v) => resolve(v as Res),
        reject,
      });
      this.transport.send(encodeRpc({ kind: "rpc-call", call_id, method, request: initial ?? null }));
      void (async () => {
        let seq = 0;
        try {
          for await (const r of requests) {
            this.transport.send(
              encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: true, value: r }),
            );
            seq += 1;
          }
          this.transport.send(
            encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: false }),
          );
        } catch (err) {
          this.transport.send(
            encodeRpc({
              kind: "rpc-client-stream",
              call_id,
              seq,
              more: false,
              error: { code: "internal", message: (err as Error).message },
            }),
          );
        }
      })();
    });
  }

  /** Bidi-streaming: each side emits N messages independently. The
   *  returned iterable yields server-side values; the supplied
   *  AsyncIterable feeds the client-side messages. */
  bidiStream<Req, Res>(
    method: string,
    requests: AsyncIterable<Req>,
    initial?: Req,
  ): AsyncIterable<Res> {
    const call_id = newCallId();
    const queue: Res[] = [];
    const awaiters: ((v: IteratorResult<Res>) => void)[] = [];
    let done = false;
    let error: RpcCallError | null = null;
    const pending: PendingStream = {
      kind: "stream",
      nextSeq: 0,
      push: (v) => {
        const typed = v as Res;
        if (awaiters.length > 0) awaiters.shift()!({ value: typed, done: false });
        else queue.push(typed);
      },
      done: () => {
        done = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined as unknown as Res, done: true });
      },
      fail: (err) => {
        error = err;
        done = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined as unknown as Res, done: true });
      },
    };
    this.pending.set(call_id, pending);
    this.transport.send(encodeRpc({ kind: "rpc-call", call_id, method, request: initial ?? null }));
    // Pump client side.
    void (async () => {
      let seq = 0;
      try {
        for await (const r of requests) {
          this.transport.send(
            encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: true, value: r }),
          );
          seq += 1;
        }
        this.transport.send(
          encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: false }),
        );
      } catch (err) {
        this.transport.send(
          encodeRpc({
            kind: "rpc-client-stream",
            call_id,
            seq,
            more: false,
            error: { code: "internal", message: (err as Error).message },
          }),
        );
      }
    })();
    const self = this;
    return {
      [Symbol.asyncIterator]() {
        return {
          async next(): Promise<IteratorResult<Res>> {
            if (error) throw error;
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (done) {
              self.pending.delete(call_id);
              return { value: undefined as unknown as Res, done: true };
            }
            const next: IteratorResult<Res> = await new Promise((resolve) => awaiters.push(resolve));
            if (next.done) {
              if (error) throw error;
              self.pending.delete(call_id);
            }
            return next;
          },
          return: async (): Promise<IteratorResult<Res>> => {
            self.pending.delete(call_id);
            return { value: undefined as unknown as Res, done: true };
          },
        };
      },
    };
  }

  /** Subscribe is a server-streaming variant whose first message is the
   *  subscription request and whose subsequent messages are events. */
  subscribe<Req, V>(method: string, request: Req): AsyncIterable<V> {
    return this.serverStream<Req, V>(method, request);
  }

  /** Telemetry — push-only client-streaming with no aggregated response. */
  async telemetry<Req>(method: string, frames: AsyncIterable<Req>): Promise<void> {
    await this.clientStream<Req, unknown>(method, frames);
  }

  async *serverStream<Req, V>(method: string, request: Req): AsyncIterable<V> {
    const call_id = newCallId();
    const queue: V[] = [];
    const awaiters: ((v: IteratorResult<V>) => void)[] = [];
    let done = false;
    let error: RpcCallError | null = null;

    const pending: PendingStream = {
      kind: "stream",
      nextSeq: 0,
      push: (v) => {
        const typed = v as V;
        if (awaiters.length > 0) {
          awaiters.shift()!({ value: typed, done: false });
        } else {
          queue.push(typed);
        }
      },
      done: () => {
        done = true;
        while (awaiters.length > 0) {
          awaiters.shift()!({ value: undefined as unknown as V, done: true });
        }
      },
      fail: (err) => {
        error = err;
        done = true;
        while (awaiters.length > 0) {
          awaiters.shift()!({ value: undefined as unknown as V, done: true });
        }
      },
    };
    this.pending.set(call_id, pending);
    this.transport.send(encodeRpc({ kind: "rpc-call", call_id, method, request }));

    try {
      while (true) {
        if (error) throw error;
        if (queue.length > 0) {
          yield queue.shift()!;
          continue;
        }
        if (done) return;
        const next: IteratorResult<V> = await new Promise((resolve) => awaiters.push(resolve));
        if (next.done) {
          if (error) throw error;
          return;
        }
        yield next.value;
      }
    } finally {
      this.pending.delete(call_id);
    }
  }

  private onFrame(sessionFrame: SessionFrame): void {
    const rpc = decodeRpc(sessionFrame);
    if (!rpc) return;

    if (rpc.kind === "rpc-response") {
      const p = this.pending.get(rpc.call_id);
      if (!p || p.kind !== "unary") return;
      this.pending.delete(rpc.call_id);
      if (rpc.status === "ok") {
        p.resolve(rpc.response);
        this.options.onProofEvent?.({
          type: "rpc.call",
          call_id: rpc.call_id,
          caller: this.options.callerActor,
          method: "(client)",
          result: "ok",
        });
      } else {
        const err = rpc.error ?? { code: "internal", message: "(no error body)" };
        p.reject(new RpcCallError(err));
        this.options.onProofEvent?.({
          type: "rpc.call",
          call_id: rpc.call_id,
          caller: this.options.callerActor,
          method: "(client)",
          result: "error",
          error_code: err.code,
        });
      }
      return;
    }

    if (rpc.kind === "rpc-stream") {
      const p = this.pending.get(rpc.call_id);
      if (!p || p.kind !== "stream") return;
      if (rpc.seq !== p.nextSeq) {
        p.fail(new RpcCallError({ code: "internal", message: `stream seq mismatch: expected ${p.nextSeq}, got ${rpc.seq}` }));
        return;
      }
      p.nextSeq += 1;
      if (rpc.more) {
        p.push(rpc.value);
      } else if (rpc.error) {
        p.fail(new RpcCallError(rpc.error));
      } else {
        p.done();
      }
      return;
    }
    // rpc-call on the client side is a protocol error; ignore.
  }
}

// ---------- server ----------

export type UnaryHandler<Req = unknown, Res = unknown> = (
  request: Req,
  ctx: RpcContext,
) => Promise<Res> | Res;

export type ServerStreamHandler<Req = unknown, V = unknown> = (
  request: Req,
  ctx: RpcContext,
) => AsyncIterable<V>;

/** Client-streaming handler: receives an AsyncIterable of client
 *  messages plus the initial request, returns a single aggregated response. */
export type ClientStreamHandler<Req = unknown, Res = unknown> = (
  initial: unknown,
  messages: AsyncIterable<Req>,
  ctx: RpcContext,
) => Promise<Res> | Res;

/** Bidi-streaming handler: receives an AsyncIterable of client messages
 *  plus the initial request and returns an AsyncIterable of server
 *  messages. The runtime guarantees independent flow control. */
export type BidiStreamHandler<Req = unknown, Res = unknown> = (
  initial: unknown,
  messages: AsyncIterable<Req>,
  ctx: RpcContext,
) => AsyncIterable<Res>;

export interface RpcContext {
  /** Cryptographic, key-derived caller URI. The authoritative identity. */
  callerActor: string;
  /** The peer's self-claimed actor URI from `peer_hint`. Advisory only. */
  callerClaim?: string;
  method: string;
  callId: string;
}

type Handler =
  | { kind: "unary"; capability: string; handler: UnaryHandler }
  | { kind: "server-streaming"; capability: string; handler: ServerStreamHandler }
  | { kind: "client-streaming"; capability: string; handler: ClientStreamHandler }
  | { kind: "bidi-streaming"; capability: string; handler: BidiStreamHandler };

interface InflightCall {
  method: string;
  capability: string;
  seq: number;
  cancel: () => void;
  /** Optional client-stream queue for client-streaming / bidi calls. */
  clientStream?: ClientStreamQueue;
}

interface ClientStreamQueue {
  push(value: unknown): void;
  done(): void;
  fail(err: RpcError): void;
}

export interface RpcServerOptions {
  selfActor: string;
  enforcer?: CapabilityEnforcer;
  /** Static fallback caller actor URI. The session-derived caller (via
   *  `getCaller`) takes precedence; this is only used when the server is
   *  driven by a transport that does not surface a peer identity (e.g.
   *  in-process tests). Production daemons MUST supply `getCaller`. */
  callerActor?: string;
  /** Returns the canonical, key-derived peer actor URI for the current
   *  request. The daemon wires this to `endpoint.peerActor()`. When this
   *  callback is set, every guard check + proof event uses its return
   *  value instead of `callerActor`. */
  getCaller?: () => string;
  /** Returns the peer's self-claimed actor URI from `peer_hint`. Advisory
   *  only — not used for authority. Surfaced in proof events under
   *  `caller_claim`. */
  getCallerClaim?: () => string | undefined;
  onProofEvent?: (ev: RpcProofEventStub) => void;
  /** Triggers that force the server to re-run capability enforcement on
   *  in-flight server-streaming responses. Maps to TF-0004's
   *  `continuous_reevaluation`. */
  continuousReevaluation?: ContinuousReevaluationOptions;
}

export interface ContinuousReevaluationOptions {
  triggers: Array<"time" | "delegation_change" | "revocation" | "session_rekey" | "explicit_reauth">;
  /** Re-check interval for `time` trigger, in ms. Default 30000. */
  intervalMs?: number;
}

export class RpcServer {
  private handlers = new Map<string, Handler>();
  private inflight = new Map<string, InflightCall>();
  private timeReevalTimer?: ReturnType<typeof setInterval>;

  constructor(private transport: RpcTransport, private opts: RpcServerOptions) {
    this.transport.onFrame((f) => this.onFrame(f));
    if (opts.continuousReevaluation?.triggers.includes("time")) {
      const interval = opts.continuousReevaluation.intervalMs ?? 30_000;
      this.timeReevalTimer = setInterval(() => {
        void this.reevaluateAll("time");
      }, interval);
    }
  }

  /** Trigger continuous reevaluation. Server-streaming calls in flight
   *  will have their capability re-checked; if the re-check no longer
   *  permits the call, the stream is closed with permission_denied. */
  async reevaluate(trigger: ContinuousReevaluationOptions["triggers"][number]): Promise<void> {
    if (!this.opts.continuousReevaluation?.triggers.includes(trigger)) return;
    await this.reevaluateAll(trigger);
  }

  private currentCaller(): string {
    if (this.opts.getCaller) return this.opts.getCaller();
    return this.opts.callerActor ?? "tf:actor:process:local/anonymous";
  }

  private currentCallerClaim(): string | undefined {
    return this.opts.getCallerClaim?.();
  }

  private async reevaluateAll(trigger: string): Promise<void> {
    const enforcer = this.opts.enforcer ?? allowAllEnforcer;
    const caller = this.currentCaller();
    for (const [callId, call] of [...this.inflight]) {
      try {
        const verdict = await Promise.resolve(enforcer.check(caller, call.method, call.capability));
        if (verdict !== "allow") {
          this.transport.send(
            encodeRpc({
              kind: "rpc-stream",
              call_id: callId,
              seq: call.seq,
              more: false,
              error: { code: "permission_denied", message: `revoked on ${trigger}: ${verdict.deny}` },
            }),
          );
          this.opts.onProofEvent?.({
            type: "rpc.call",
            call_id: callId,
            method: call.method,
            caller,
            result: "error",
            error_code: "permission_denied",
          });
          this.inflight.delete(callId);
          call.cancel();
        }
      } catch {
        // ignore enforcer errors during reeval; next call will surface them
      }
    }
  }

  /** Stop background reevaluation timers. Call when shutting the server down. */
  shutdown(): void {
    if (this.timeReevalTimer) {
      clearInterval(this.timeReevalTimer);
      this.timeReevalTimer = undefined;
    }
    for (const [, call] of this.inflight) call.cancel();
    this.inflight.clear();
  }

  registerUnary<Req, Res>(method: string, capability: string, handler: UnaryHandler<Req, Res>): void {
    this.handlers.set(method, {
      kind: "unary",
      capability,
      handler: handler as UnaryHandler,
    });
  }

  registerServerStream<Req, V>(method: string, capability: string, handler: ServerStreamHandler<Req, V>): void {
    this.handlers.set(method, {
      kind: "server-streaming",
      capability,
      handler: handler as ServerStreamHandler,
    });
  }

  registerClientStream<Req, Res>(method: string, capability: string, handler: ClientStreamHandler<Req, Res>): void {
    this.handlers.set(method, {
      kind: "client-streaming",
      capability,
      handler: handler as ClientStreamHandler,
    });
  }

  registerBidiStream<Req, Res>(method: string, capability: string, handler: BidiStreamHandler<Req, Res>): void {
    this.handlers.set(method, {
      kind: "bidi-streaming",
      capability,
      handler: handler as BidiStreamHandler,
    });
  }

  /** Subscribe is a server-streaming method with explicit subscribe semantics. */
  registerSubscribe<Req, V>(method: string, capability: string, handler: ServerStreamHandler<Req, V>): void {
    this.registerServerStream(method, capability, handler);
  }

  /** Telemetry is a client-streaming method that aggregates frames into
   *  a void response. */
  registerTelemetry<Req>(
    method: string,
    capability: string,
    handler: (initial: unknown, frames: AsyncIterable<Req>, ctx: RpcContext) => Promise<void> | void,
  ): void {
    this.registerClientStream<Req, null>(method, capability, async (initial, frames, ctx) => {
      await handler(initial, frames, ctx);
      return null;
    });
  }

  private async onFrame(sessionFrame: SessionFrame): Promise<void> {
    const rpc = decodeRpc(sessionFrame);
    if (!rpc) return;

    // Route incoming client-stream messages to the matching in-flight call.
    if (rpc.kind === "rpc-client-stream") {
      const call = this.inflight.get(rpc.call_id);
      if (!call?.clientStream) return;
      if (rpc.error) call.clientStream.fail(rpc.error);
      else if (rpc.more) call.clientStream.push(rpc.value);
      else call.clientStream.done();
      return;
    }
    if (rpc.kind !== "rpc-call") return;

    const caller = this.currentCaller();
    const callerClaim = this.currentCallerClaim();
    const ctx: RpcContext = {
      callerActor: caller,
      callerClaim,
      method: rpc.method,
      callId: rpc.call_id,
    };

    const registered = this.handlers.get(rpc.method);
    if (!registered) {
      this.sendError(rpc.call_id, { code: "not_found", message: `unknown method: ${rpc.method}` }, ctx, false);
      return;
    }

    const enforcer = this.opts.enforcer ?? allowAllEnforcer;
    let decision: CapabilityVerdict;
    try {
      decision = await Promise.resolve(enforcer.check(caller, rpc.method, registered.capability));
    } catch (err) {
      const message = (err as Error).message ?? String(err);
      this.sendError(
        rpc.call_id,
        { code: "internal", message: `capability enforcer threw: ${message}` },
        ctx,
        registered.kind === "server-streaming" || registered.kind === "bidi-streaming",
      );
      return;
    }
    if (decision !== "allow") {
      this.sendError(
        rpc.call_id,
        { code: "permission_denied", message: decision.deny },
        ctx,
        registered.kind === "server-streaming" || registered.kind === "bidi-streaming",
      );
      return;
    }

    if (registered.kind === "unary") {
      try {
        const res = await registered.handler(rpc.request, ctx);
        this.transport.send(
          encodeRpc({ kind: "rpc-response", call_id: rpc.call_id, status: "ok", response: res }),
        );
        this.opts.onProofEvent?.({ type: "rpc.call", call_id: rpc.call_id, method: rpc.method, caller, result: "ok" });
      } catch (err) {
        const message = (err as Error).message ?? String(err);
        this.sendError(rpc.call_id, { code: "internal", message }, ctx, false);
      }
      return;
    }

    if (registered.kind === "client-streaming" || registered.kind === "bidi-streaming") {
      // Build an AsyncIterable<unknown> the handler consumes.
      const queue: unknown[] = [];
      const awaiters: Array<(v: IteratorResult<unknown>) => void> = [];
      let streamDone = false;
      let streamError: RpcError | null = null;
      const cs: ClientStreamQueue = {
        push: (v) => {
          if (awaiters.length > 0) awaiters.shift()!({ value: v, done: false });
          else queue.push(v);
        },
        done: () => {
          streamDone = true;
          while (awaiters.length > 0)
            awaiters.shift()!({ value: undefined, done: true });
        },
        fail: (err) => {
          streamError = err;
          streamDone = true;
          while (awaiters.length > 0)
            awaiters.shift()!({ value: undefined, done: true });
        },
      };
      const iter: AsyncIterable<unknown> = {
        [Symbol.asyncIterator]() {
          return {
            async next(): Promise<IteratorResult<unknown>> {
              if (streamError) throw new RpcCallError(streamError);
              if (queue.length > 0) return { value: queue.shift(), done: false };
              if (streamDone) return { value: undefined, done: true };
              return new Promise((resolve) => awaiters.push(resolve));
            },
          };
        },
      };
      const inflight: InflightCall = {
        method: rpc.method,
        capability: registered.capability,
        seq: 0,
        cancel: () => {
          streamDone = true;
        },
        clientStream: cs,
      };
      this.inflight.set(rpc.call_id, inflight);
      if (registered.kind === "client-streaming") {
        try {
          const res = await registered.handler(rpc.request, iter, ctx);
          this.transport.send(
            encodeRpc({ kind: "rpc-response", call_id: rpc.call_id, status: "ok", response: res }),
          );
          this.opts.onProofEvent?.({ type: "rpc.call", call_id: rpc.call_id, method: rpc.method, caller, result: "ok" });
        } catch (err) {
          const message = (err as Error).message ?? String(err);
          this.sendError(rpc.call_id, { code: "internal", message }, ctx, false);
        } finally {
          this.inflight.delete(rpc.call_id);
        }
        return;
      }
      // bidi-streaming
      let seq = 0;
      let cancelled = false;
      inflight.cancel = () => {
        cancelled = true;
        streamDone = true;
      };
      try {
        for await (const value of registered.handler(rpc.request, iter, ctx)) {
          if (cancelled) break;
          this.transport.send(
            encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: true, value }),
          );
          seq += 1;
          inflight.seq = seq;
        }
        if (!cancelled) {
          this.transport.send(
            encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: false }),
          );
          this.opts.onProofEvent?.({ type: "rpc.call", call_id: rpc.call_id, method: rpc.method, caller, result: "ok" });
        }
      } catch (err) {
        if (!cancelled) {
          const message = (err as Error).message ?? String(err);
          this.transport.send(
            encodeRpc({
              kind: "rpc-stream",
              call_id: rpc.call_id,
              seq,
              more: false,
              error: { code: "internal", message },
            }),
          );
          this.opts.onProofEvent?.({
            type: "rpc.call",
            call_id: rpc.call_id,
            method: rpc.method,
            caller,
            result: "error",
            error_code: "internal",
          });
        }
      } finally {
        this.inflight.delete(rpc.call_id);
      }
      return;
    }

    // server-streaming
    let seq = 0;
    let cancelled = false;
    const inflight: InflightCall = {
      method: rpc.method,
      capability: registered.capability,
      seq,
      cancel: () => {
        cancelled = true;
      },
    };
    this.inflight.set(rpc.call_id, inflight);
    try {
      for await (const value of registered.handler(rpc.request, ctx)) {
        if (cancelled) break;
        this.transport.send(
          encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: true, value }),
        );
        seq += 1;
        inflight.seq = seq;
      }
      if (!cancelled) {
        this.transport.send(
          encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: false }),
        );
        this.opts.onProofEvent?.({ type: "rpc.call", call_id: rpc.call_id, method: rpc.method, caller, result: "ok" });
      }
    } catch (err) {
      if (!cancelled) {
        const message = (err as Error).message ?? String(err);
        this.transport.send(
          encodeRpc({
            kind: "rpc-stream",
            call_id: rpc.call_id,
            seq,
            more: false,
            error: { code: "internal", message },
          }),
        );
        this.opts.onProofEvent?.({
          type: "rpc.call",
          call_id: rpc.call_id,
          method: rpc.method,
          caller,
          result: "error",
          error_code: "internal",
        });
      }
    } finally {
      this.inflight.delete(rpc.call_id);
    }
  }

  private sendError(call_id: string, error: RpcError, ctx: RpcContext, streaming: boolean): void {
    if (streaming) {
      this.transport.send(
        encodeRpc({ kind: "rpc-stream", call_id, seq: 0, more: false, error }),
      );
    } else {
      this.transport.send(encodeRpc({ kind: "rpc-response", call_id, status: "error", error }));
    }
    this.opts.onProofEvent?.({
      type: "rpc.call",
      call_id,
      method: ctx.method,
      caller: ctx.callerActor,
      result: "error",
      error_code: error.code,
    });
  }
}
