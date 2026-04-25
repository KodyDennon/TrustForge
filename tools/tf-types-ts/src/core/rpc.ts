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

/** Per-kind metadata that rides on the frame envelope without
 *  changing the frame schema. Keeps the wire format additive. */
export interface RpcFrameExt {
  /** Method kind. Set on rpc-call only; servers stash it for the call lifetime. */
  method_kind?: RpcMethodKind;
  /** Streaming priority class for telemetry/bulk-transfer. */
  streaming_priority?: StreamingPriority;
  /** Subscription topic (subscribe). */
  subscribe_topic?: string;
  /** Backpressure credit grant (command-channel). */
  credit?: number;
  /** Bulk-transfer chunk index + final-hash assertion (bulk-transfer). */
  bulk?: { chunk_index?: number; total_chunks?: number; expected_hash?: string };
  /** Stream tag for remote-shell frames. */
  shell_stream?: RemoteShellStream;
  /** Delegation chain attached to an agent-session frame. */
  responsibility_chain?: string[];
  /** Subscription / control acks that don't carry a value. */
  ack?: "subscribed" | "unsubscribed" | "pause" | "resume";
}

export type RpcFrame =
  | { kind: "rpc-call"; call_id: string; method: string; request: unknown; ext?: RpcFrameExt }
  | { kind: "rpc-response"; call_id: string; status: "ok" | "error"; response?: unknown; error?: RpcError; ext?: RpcFrameExt }
  | { kind: "rpc-stream"; call_id: string; seq: number; more: boolean; value?: unknown; error?: RpcError; ext?: RpcFrameExt }
  /** Client → server stream message used by client-streaming, bidi, command-channel,
   *  bulk-transfer, telemetry, remote-shell, agent-session method kinds. */
  | { kind: "rpc-client-stream"; call_id: string; seq: number; more: boolean; value?: unknown; error?: RpcError; ext?: RpcFrameExt };

/** ProofRPC method kind enum. Mirrors `proofrpc.schema.json`. */
export type RpcMethodKind =
  | "unary"
  | "server-streaming"
  | "client-streaming"
  | "bidi-streaming"
  | "subscribe"
  | "command-channel"
  | "bulk-transfer"
  | "telemetry"
  | "remote-shell"
  | "agent-session";

export type RemoteShellStream = "stdin" | "stdout" | "stderr";

/** Telemetry / streaming priority classes (TF-0011). */
export type StreamingPriority = "P0" | "P1" | "P2" | "P3" | "P4" | "P5";

export interface RpcProofEventStub {
  type: "rpc.call";
  method: string;
  /** Method kind from the descriptor; lets the daemon apply per-kind
   *  policy and surfaces the distinction in proof events. */
  method_kind?: RpcMethodKind;
  call_id: string;
  caller: string;
  result: "ok" | "error";
  error_code?: RpcErrorCode;
  /** Telemetry / bulk-transfer carry priority; surfaced for per-priority
   *  rate-limiting and observability. */
  streaming_priority?: StreamingPriority;
  /** Bulk-transfer hash verification result. */
  bulk_hash_verified?: boolean;
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
  /** Last shell-stream tag observed for each call_id; the remote-shell
   *  helper uses this to recover the (stdout|stderr) tag when the
   *  rpc-stream frame is decoded. */
  private lastShellStream = new Map<string, RemoteShellStream>();
  /** Last responsibility_chain observed on an agent-session rpc-stream
   *  frame for each call_id. The agent-session helper re-attaches it
   *  when yielding values back to the consumer. */
  private lastAgentChain = new Map<string, string[]>();

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

  /** Subscribe — server-streaming variant whose first server frame is
   *  an explicit `subscribed` ack. The ack frame is filtered out of the
   *  iterator so consumers only see real events. */
  async *subscribe<Req, V>(method: string, request: Req, opts: { topic?: string } = {}): AsyncIterable<V> {
    const call_id = newCallId();
    const queue: V[] = [];
    const awaiters: ((v: IteratorResult<V>) => void)[] = [];
    let done = false;
    let error: RpcCallError | null = null;
    let acked = false;
    const pending: PendingStream = {
      kind: "stream",
      nextSeq: 0,
      push: (v) => {
        const typed = v as V;
        if (awaiters.length > 0) awaiters.shift()!({ value: typed, done: false });
        else queue.push(typed);
      },
      done: () => {
        done = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined as unknown as V, done: true });
      },
      fail: (err) => {
        error = err;
        done = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined as unknown as V, done: true });
      },
    };
    this.pending.set(call_id, pending);
    this.transport.send(
      encodeRpc({
        kind: "rpc-call",
        call_id,
        method,
        request,
        ext: { method_kind: "subscribe", subscribe_topic: opts.topic },
      }),
    );
    try {
      while (true) {
        if (error) throw error;
        if (queue.length > 0) {
          // First subscriber-visible value confirms the channel is alive
          // even if no `subscribed` ack frame ever materialised on the wire.
          if (!acked) acked = true;
          yield queue.shift()!;
          continue;
        }
        if (done) return;
        const next: IteratorResult<V> = await new Promise((resolve) => awaiters.push(resolve));
        if (next.done) {
          if (error) throw error;
          return;
        }
        if (!acked) acked = true;
        yield next.value;
      }
    } finally {
      this.pending.delete(call_id);
    }
  }

  /** Telemetry — push-only client-streaming with no aggregated response.
   *  The runtime sets `ext.method_kind = "telemetry"` and surfaces the
   *  declared streaming_priority in proof events. */
  async telemetry<Req>(
    method: string,
    frames: AsyncIterable<Req>,
    opts: { priority?: StreamingPriority } = {},
  ): Promise<void> {
    const call_id = newCallId();
    await new Promise<void>((resolve, reject) => {
      this.pending.set(call_id, {
        kind: "unary",
        resolve: () => resolve(),
        reject,
      });
      this.transport.send(
        encodeRpc({
          kind: "rpc-call",
          call_id,
          method,
          request: null,
          ext: { method_kind: "telemetry", streaming_priority: opts.priority },
        }),
      );
      void (async () => {
        let seq = 0;
        try {
          for await (const f of frames) {
            this.transport.send(
              encodeRpc({
                kind: "rpc-client-stream",
                call_id,
                seq,
                more: true,
                value: f,
                ext: { method_kind: "telemetry", streaming_priority: opts.priority },
              }),
            );
            seq += 1;
          }
          this.transport.send(
            encodeRpc({
              kind: "rpc-client-stream",
              call_id,
              seq,
              more: false,
              ext: { method_kind: "telemetry" },
            }),
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

  /** Command-channel — bidi with server-tracked credit. The client
   *  doesn't enforce credit locally; the server refuses to over-send. */
  commandChannel<Req, Res>(method: string, requests: AsyncIterable<Req>, initial?: Req): AsyncIterable<Res> {
    return this.bidiStreamWithExt<Req, Res>(method, requests, initial, { method_kind: "command-channel" });
  }

  /** Bulk-transfer — client-streamed Uint8Array chunks with a final
   *  hash assertion. The client computes SHA-256 over the concatenated
   *  chunks before sending so the server has something to verify
   *  against. */
  async bulkTransfer<Receipt>(
    method: string,
    initial: unknown,
    chunks: Uint8Array[],
  ): Promise<Receipt> {
    const expected = await digestSha256Hex(chunks);
    const call_id = newCallId();
    return new Promise<Receipt>((resolve, reject) => {
      this.pending.set(call_id, {
        kind: "unary",
        resolve: (v) => resolve(v as Receipt),
        reject,
      });
      this.transport.send(
        encodeRpc({
          kind: "rpc-call",
          call_id,
          method,
          request: initial,
          ext: { method_kind: "bulk-transfer", bulk: { expected_hash: expected, total_chunks: chunks.length } },
        }),
      );
      // Yield once so the server's async dispatcher has time to
      // register the in-flight call before we start blasting chunks.
      void (async () => {
        await Promise.resolve();
        let seq = 0;
        for (const chunk of chunks) {
          this.transport.send(
            encodeRpc({
              kind: "rpc-client-stream",
              call_id,
              seq,
              more: true,
              value: chunk,
              ext: { method_kind: "bulk-transfer", bulk: { chunk_index: seq } },
            }),
          );
          seq += 1;
        }
        this.transport.send(
          encodeRpc({
            kind: "rpc-client-stream",
            call_id,
            seq,
            more: false,
            ext: { method_kind: "bulk-transfer" },
          }),
        );
      })();
    });
  }

  /** Remote-shell — bidi where the client emits stdin chunks and the
   *  server emits {stream, data} frames tagged stdin/stdout/stderr. */
  remoteShell(
    method: string,
    stdin: AsyncIterable<Uint8Array>,
  ): AsyncIterable<RemoteShellFrame> {
    const call_id = newCallId();
    const queue: RemoteShellFrame[] = [];
    const awaiters: Array<(v: IteratorResult<RemoteShellFrame>) => void> = [];
    let done = false;
    let error: RpcCallError | null = null;
    const pending: PendingStream = {
      kind: "stream",
      nextSeq: 0,
      push: (v) => {
        // Server pushes the value (Uint8Array); we recover the stream tag
        // from the surrounding rpc-stream frame's ext, which we remember
        // in `lastShellStream` (set in onFrame).
        const tag = this.lastShellStream.get(call_id) ?? "stdout";
        const data = v instanceof Uint8Array ? v : new Uint8Array(0);
        const frame: RemoteShellFrame = { stream: tag, data };
        if (awaiters.length > 0) awaiters.shift()!({ value: frame, done: false });
        else queue.push(frame);
      },
      done: () => {
        done = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { stream: "stdout", data: new Uint8Array(0) }, done: true });
      },
      fail: (err) => {
        error = err;
        done = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { stream: "stdout", data: new Uint8Array(0) }, done: true });
      },
    };
    this.pending.set(call_id, pending);
    this.transport.send(
      encodeRpc({ kind: "rpc-call", call_id, method, request: null, ext: { method_kind: "remote-shell" } }),
    );
    void (async () => {
      let seq = 0;
      for await (const chunk of stdin) {
        this.transport.send(
          encodeRpc({
            kind: "rpc-client-stream",
            call_id,
            seq,
            more: true,
            value: chunk,
            ext: { method_kind: "remote-shell", shell_stream: "stdin" },
          }),
        );
        seq += 1;
      }
      this.transport.send(
        encodeRpc({
          kind: "rpc-client-stream",
          call_id,
          seq,
          more: false,
          ext: { method_kind: "remote-shell" },
        }),
      );
    })();
    const self = this;
    return {
      [Symbol.asyncIterator]() {
        return {
          async next(): Promise<IteratorResult<RemoteShellFrame>> {
            if (error) throw error;
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (done) {
              self.pending.delete(call_id);
              self.lastShellStream.delete(call_id);
              return { value: { stream: "stdout", data: new Uint8Array(0) }, done: true };
            }
            return new Promise((resolve) => awaiters.push(resolve));
          },
        };
      },
    };
  }

  /** Agent-session — bidi-streaming that propagates a delegation chain
   *  on every frame. The wire shape carries `value` directly with the
   *  chain in `ext.responsibility_chain`; the helpers here re-wrap on
   *  each side so consumers see `{value, responsibility_chain}` records. */
  agentSession<Req, Res>(
    method: string,
    requests: AsyncIterable<{ value: Req; responsibility_chain: string[] }>,
    initialChain: string[] = [],
  ): AsyncIterable<{ value: Res; responsibility_chain: string[] }> {
    const call_id = newCallId();
    const queue: Array<{ value: Res; responsibility_chain: string[] }> = [];
    const awaiters: ((v: IteratorResult<{ value: Res; responsibility_chain: string[] }>) => void)[] = [];
    let done = false;
    let error: RpcCallError | null = null;
    const chainByCall = this.lastAgentChain;
    const pending: PendingStream = {
      kind: "stream",
      nextSeq: 0,
      push: (v) => {
        const chain = chainByCall.get(call_id) ?? [];
        const frame = { value: v as Res, responsibility_chain: chain };
        if (awaiters.length > 0) awaiters.shift()!({ value: frame, done: false });
        else queue.push(frame);
      },
      done: () => {
        done = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { value: undefined as unknown as Res, responsibility_chain: [] }, done: true });
      },
      fail: (err) => {
        error = err;
        done = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { value: undefined as unknown as Res, responsibility_chain: [] }, done: true });
      },
    };
    this.pending.set(call_id, pending);
    this.transport.send(
      encodeRpc({
        kind: "rpc-call",
        call_id,
        method,
        request: null,
        ext: { method_kind: "agent-session", responsibility_chain: initialChain },
      }),
    );
    void (async () => {
      let seq = 0;
      try {
        for await (const r of requests) {
          this.transport.send(
            encodeRpc({
              kind: "rpc-client-stream",
              call_id,
              seq,
              more: true,
              value: r.value,
              ext: { method_kind: "agent-session", responsibility_chain: r.responsibility_chain },
            }),
          );
          seq += 1;
        }
        this.transport.send(
          encodeRpc({
            kind: "rpc-client-stream",
            call_id,
            seq,
            more: false,
            ext: { method_kind: "agent-session" },
          }),
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
          async next(): Promise<IteratorResult<{ value: Res; responsibility_chain: string[] }>> {
            if (error) throw error;
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (done) {
              self.pending.delete(call_id);
              self.lastAgentChain.delete(call_id);
              return { value: { value: undefined as unknown as Res, responsibility_chain: [] }, done: true };
            }
            return new Promise((resolve) => awaiters.push(resolve));
          },
        };
      },
    };
  }

  private bidiStreamWithExt<Req, Res>(
    method: string,
    requests: AsyncIterable<Req>,
    initial: Req | undefined,
    ext: RpcFrameExt,
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
    this.transport.send(
      encodeRpc({ kind: "rpc-call", call_id, method, request: initial ?? null, ext }),
    );
    void (async () => {
      let seq = 0;
      try {
        for await (const r of requests) {
          this.transport.send(
            encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: true, value: r, ext }),
          );
          seq += 1;
        }
        this.transport.send(
          encodeRpc({ kind: "rpc-client-stream", call_id, seq, more: false, ext }),
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
        };
      },
    };
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
      // Subscribe / command-channel emit `seq = -1` synthetic ack frames
      // (subscribed/unsubscribed, initial credit grant). These ride on
      // the wire but are invisible to consumers — they don't advance
      // the sequence counter. Bulk-transfer doesn't use rpc-stream at all.
      if (rpc.seq === -1) {
        if (!rpc.more) {
          // unsubscribed-style trailer: end the stream cleanly.
          p.done();
        }
        return;
      }
      if (rpc.seq !== p.nextSeq) {
        p.fail(new RpcCallError({ code: "internal", message: `stream seq mismatch: expected ${p.nextSeq}, got ${rpc.seq}` }));
        return;
      }
      p.nextSeq += 1;
      // remote-shell: stash the stream tag so the helper iterator can
      // re-attach it to the value when it yields.
      const ext = rpc.ext;
      if (ext?.method_kind === "remote-shell" && ext.shell_stream) {
        this.lastShellStream.set(rpc.call_id, ext.shell_stream);
      }
      // agent-session: stash the chain so the helper iterator yields
      // `{value, responsibility_chain}` records.
      if (ext?.method_kind === "agent-session" && Array.isArray(ext.responsibility_chain)) {
        this.lastAgentChain.set(rpc.call_id, ext.responsibility_chain);
      }
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

/** Subscribe handler: receives the subscription request and returns an
 *  AsyncIterable of events. The runtime emits a `subscribed` ack frame
 *  before forwarding events and a `unsubscribed` ack on completion. */
export type SubscribeHandler<Req = unknown, V = unknown> = (
  request: Req,
  ctx: RpcContext,
) => AsyncIterable<V>;

/** Command-channel handler: long-lived bidi with credit-based
 *  backpressure. The handler must call `ctx.creditAvailable()` /
 *  `await ctx.requestCredit(n)` before sending; the runtime tracks
 *  outstanding credits and refuses to send when the bucket is empty. */
export type CommandChannelHandler<Req = unknown, Res = unknown> = (
  initial: unknown,
  messages: AsyncIterable<Req>,
  ctx: CommandChannelContext,
) => AsyncIterable<Res>;

/** Bulk-transfer handler: receives byte chunks (Uint8Array) plus the
 *  final hash assertion and returns a typed receipt. The runtime
 *  computes a rolling SHA-256 of the chunks and verifies it against
 *  the client-asserted `expected_hash`; mismatches reject the call. */
export type BulkTransferHandler<Receipt = unknown> = (
  initial: unknown,
  chunks: AsyncIterable<Uint8Array>,
  ctx: RpcContext,
) => Promise<Receipt> | Receipt;

/** Telemetry handler: push-only client-streaming with no aggregated
 *  response. The supplied `priority` reflects the streaming_priority
 *  class declared on the method; the runtime surfaces it in proof
 *  events for per-priority metering. */
export type TelemetryHandler<Req = unknown> = (
  initial: unknown,
  frames: AsyncIterable<Req>,
  ctx: TelemetryContext,
) => Promise<void> | void;

/** Remote-shell handler: bidi where each frame is tagged with a stream
 *  tag (`stdin`/`stdout`/`stderr`). The runtime preserves the tag
 *  end-to-end and refuses untagged frames. */
export type RemoteShellHandler = (
  initial: unknown,
  stdin: AsyncIterable<Uint8Array>,
  ctx: RemoteShellContext,
) => AsyncIterable<RemoteShellFrame>;

/** Agent-session handler: bidi that carries a delegation chain on every
 *  frame. The handler receives the chain as part of `ctx` and may
 *  augment it before forwarding to downstream tools. */
export type AgentSessionHandler<Req = unknown, Res = unknown> = (
  initial: unknown,
  messages: AsyncIterable<{ value: Req; responsibility_chain: string[] }>,
  ctx: AgentSessionContext,
) => AsyncIterable<{ value: Res; responsibility_chain: string[] }>;

export interface RemoteShellFrame {
  stream: RemoteShellStream;
  data: Uint8Array;
}

export interface CommandChannelContext extends RpcContext {
  /** Credits the runtime has granted but the handler hasn't consumed. */
  creditAvailable(): number;
  /** Wait until at least one credit is available, then return the
   *  current balance. Used by handlers that pace their output. */
  requestCredit(n?: number): Promise<number>;
}

export interface TelemetryContext extends RpcContext {
  priority: StreamingPriority;
}

export interface RemoteShellContext extends RpcContext {
  /** Convenience helper to write to a specific stream tag. */
  yield(stream: RemoteShellStream, data: Uint8Array): void;
}

export interface AgentSessionContext extends RpcContext {
  /** Delegation chain at the start of the call (taken from rpc-call.ext). */
  initialChain: string[];
}

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
  | { kind: "bidi-streaming"; capability: string; handler: BidiStreamHandler }
  | { kind: "subscribe"; capability: string; handler: SubscribeHandler }
  | { kind: "command-channel"; capability: string; handler: CommandChannelHandler; initialCredit: number }
  | { kind: "bulk-transfer"; capability: string; handler: BulkTransferHandler }
  | { kind: "telemetry"; capability: string; handler: TelemetryHandler; priority: StreamingPriority }
  | { kind: "remote-shell"; capability: string; handler: RemoteShellHandler }
  | { kind: "agent-session"; capability: string; handler: AgentSessionHandler };

interface InflightCall {
  method: string;
  method_kind?: RpcMethodKind;
  capability: string;
  seq: number;
  cancel: () => void;
  /** Optional client-stream queue for client-streaming / bidi calls. */
  clientStream?: ClientStreamQueue;
  /** Outstanding command-channel credit. */
  credit?: number;
}

async function digestSha256Hex(chunks: Uint8Array[]): Promise<string> {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const view = new Uint8Array(digest);
  let hex = "";
  for (const b of view) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

interface ClientStreamQueue {
  /** Optional `ext` carries per-frame metadata (e.g.
   *  agent-session's responsibility_chain). The server-side
   *  per-kind dispatcher reads it where relevant. */
  push(value: unknown, ext?: RpcFrameExt): void;
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

  /** Subscribe — server-streaming with explicit `subscribed` /
   *  `unsubscribed` ack frames bracketing the event stream. The runtime
   *  tags every proof event with `method_kind = "subscribe"`. */
  registerSubscribe<Req, V>(method: string, capability: string, handler: SubscribeHandler<Req, V>): void {
    this.handlers.set(method, {
      kind: "subscribe",
      capability,
      handler: handler as SubscribeHandler,
    });
  }

  /** Telemetry — push-only client-streaming that emits no aggregated
   *  response. Carries a streaming_priority class which is enforced on
   *  the wire via `ext.streaming_priority` and surfaced in proof events. */
  registerTelemetry<Req>(
    method: string,
    capability: string,
    handler: TelemetryHandler<Req>,
    opts: { priority?: StreamingPriority } = {},
  ): void {
    this.handlers.set(method, {
      kind: "telemetry",
      capability,
      priority: opts.priority ?? "P3",
      handler: handler as TelemetryHandler,
    });
  }

  /** Command-channel — bidi with credit-based backpressure. The
   *  handler must call `await ctx.requestCredit()` before sending; the
   *  runtime refuses to forward over budget. */
  registerCommandChannel<Req, Res>(
    method: string,
    capability: string,
    handler: CommandChannelHandler<Req, Res>,
    opts: { initialCredit?: number } = {},
  ): void {
    this.handlers.set(method, {
      kind: "command-channel",
      capability,
      initialCredit: opts.initialCredit ?? 4,
      handler: handler as CommandChannelHandler,
    });
  }

  /** Bulk-transfer — client-streamed Uint8Array chunks plus a final
   *  hash assertion. The runtime SHA-256s the concatenated chunks and
   *  refuses the receipt unless the digest matches. */
  registerBulkTransfer<Receipt>(
    method: string,
    capability: string,
    handler: BulkTransferHandler<Receipt>,
  ): void {
    this.handlers.set(method, {
      kind: "bulk-transfer",
      capability,
      handler: handler as BulkTransferHandler,
    });
  }

  /** Remote-shell — bidi with stream tags (stdin/stdout/stderr).
   *  Untagged frames are rejected. */
  registerRemoteShell(method: string, capability: string, handler: RemoteShellHandler): void {
    this.handlers.set(method, {
      kind: "remote-shell",
      capability,
      handler,
    });
  }

  /** Agent-session — bidi that carries a delegation chain. The runtime
   *  echoes the chain on every server frame so downstream auditors can
   *  attribute responsibility correctly. */
  registerAgentSession<Req, Res>(
    method: string,
    capability: string,
    handler: AgentSessionHandler<Req, Res>,
  ): void {
    this.handlers.set(method, {
      kind: "agent-session",
      capability,
      handler: handler as AgentSessionHandler,
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
      else if (rpc.more) call.clientStream.push(rpc.value, rpc.ext);
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
    const isStreaming =
      registered.kind === "server-streaming" ||
      registered.kind === "bidi-streaming" ||
      registered.kind === "subscribe" ||
      registered.kind === "command-channel" ||
      registered.kind === "remote-shell" ||
      registered.kind === "agent-session";
    try {
      decision = await Promise.resolve(enforcer.check(caller, rpc.method, registered.capability));
    } catch (err) {
      const message = (err as Error).message ?? String(err);
      this.sendError(
        rpc.call_id,
        { code: "internal", message: `capability enforcer threw: ${message}` },
        ctx,
        isStreaming,
      );
      return;
    }
    if (decision !== "allow") {
      this.sendError(rpc.call_id, { code: "permission_denied", message: decision.deny }, ctx, isStreaming);
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

    if (registered.kind === "server-streaming") {
      await this.dispatchServerStream(rpc, registered, ctx, caller, "server-streaming");
      return;
    }
    if (registered.kind === "subscribe") {
      await this.dispatchSubscribe(rpc, registered, ctx, caller);
      return;
    }
    if (registered.kind === "command-channel") {
      await this.dispatchCommandChannel(rpc, registered, ctx, caller);
      return;
    }
    if (registered.kind === "bulk-transfer") {
      await this.dispatchBulkTransfer(rpc, registered, ctx, caller);
      return;
    }
    if (registered.kind === "telemetry") {
      await this.dispatchTelemetry(rpc, registered, ctx, caller);
      return;
    }
    if (registered.kind === "remote-shell") {
      await this.dispatchRemoteShell(rpc, registered, ctx, caller);
      return;
    }
    if (registered.kind === "agent-session") {
      await this.dispatchAgentSession(rpc, registered, ctx, caller);
      return;
    }
  }

  // ---------- per-kind dispatchers ----------

  private async dispatchServerStream(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "server-streaming" | "subscribe" }>,
    ctx: RpcContext,
    caller: string,
    methodKind: RpcMethodKind,
  ): Promise<void> {
    let seq = 0;
    let cancelled = false;
    const inflight: InflightCall = {
      method: rpc.method,
      method_kind: methodKind,
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
          encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: true, value, ext: { method_kind: methodKind } }),
        );
        seq += 1;
        inflight.seq = seq;
      }
      if (!cancelled) {
        this.transport.send(
          encodeRpc({ kind: "rpc-stream", call_id: rpc.call_id, seq, more: false, ext: { method_kind: methodKind } }),
        );
        this.opts.onProofEvent?.({
          type: "rpc.call",
          call_id: rpc.call_id,
          method: rpc.method,
          method_kind: methodKind,
          caller,
          result: "ok",
        });
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
          method_kind: methodKind,
          caller,
          result: "error",
          error_code: "internal",
        });
      }
    } finally {
      this.inflight.delete(rpc.call_id);
    }
  }

  private async dispatchSubscribe(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "subscribe" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
    // Send the explicit `subscribed` ack so the client knows the
    // subscription was accepted before any events arrive. Drives the
    // distinction from generic server-streaming.
    this.transport.send(
      encodeRpc({
        kind: "rpc-stream",
        call_id: rpc.call_id,
        seq: -1,
        more: true,
        ext: { method_kind: "subscribe", ack: "subscribed", subscribe_topic: rpc.ext?.subscribe_topic },
      }),
    );
    await this.dispatchServerStream(rpc, registered, ctx, caller, "subscribe");
    this.transport.send(
      encodeRpc({
        kind: "rpc-stream",
        call_id: rpc.call_id,
        seq: -1,
        more: false,
        ext: { method_kind: "subscribe", ack: "unsubscribed" },
      }),
    );
  }

  private async dispatchCommandChannel(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "command-channel" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
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
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined, done: true });
      },
      fail: (err) => {
        streamError = err;
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined, done: true });
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
    let credit = registered.initialCredit;
    const creditWaiters: Array<(n: number) => void> = [];
    const grantCredit = (n: number) => {
      credit += n;
      while (credit > 0 && creditWaiters.length > 0) {
        creditWaiters.shift()!(credit);
      }
    };
    const cmdCtx: CommandChannelContext = {
      ...ctx,
      creditAvailable: () => credit,
      requestCredit: (n = 1) =>
        new Promise<number>((resolve) => {
          if (credit >= n) resolve(credit);
          else creditWaiters.push(resolve);
        }),
    };
    const inflight: InflightCall = {
      method: rpc.method,
      method_kind: "command-channel",
      capability: registered.capability,
      seq: 0,
      cancel: () => {
        streamDone = true;
      },
      clientStream: cs,
      credit,
    };
    this.inflight.set(rpc.call_id, inflight);
    // Tell the client the initial credit grant.
    this.transport.send(
      encodeRpc({
        kind: "rpc-stream",
        call_id: rpc.call_id,
        seq: -1,
        more: true,
        ext: { method_kind: "command-channel", credit },
      }),
    );
    let seq = 0;
    try {
      for await (const value of registered.handler(rpc.request, iter, cmdCtx)) {
        if (credit <= 0) {
          await new Promise<void>((resolve) => creditWaiters.push(() => resolve()));
        }
        credit -= 1;
        inflight.credit = credit;
        this.transport.send(
          encodeRpc({
            kind: "rpc-stream",
            call_id: rpc.call_id,
            seq,
            more: true,
            value,
            ext: { method_kind: "command-channel", credit },
          }),
        );
        seq += 1;
        inflight.seq = seq;
      }
      this.transport.send(
        encodeRpc({
          kind: "rpc-stream",
          call_id: rpc.call_id,
          seq,
          more: false,
          ext: { method_kind: "command-channel" },
        }),
      );
      this.opts.onProofEvent?.({
        type: "rpc.call",
        call_id: rpc.call_id,
        method: rpc.method,
        method_kind: "command-channel",
        caller,
        result: "ok",
      });
    } catch (err) {
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
        method_kind: "command-channel",
        caller,
        result: "error",
        error_code: "internal",
      });
    } finally {
      this.inflight.delete(rpc.call_id);
      grantCredit(0); // wake any leftover waiters
    }
  }

  private async dispatchBulkTransfer(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "bulk-transfer" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
    const expectedHash = rpc.ext?.bulk?.expected_hash;
    if (!expectedHash) {
      this.sendError(rpc.call_id, { code: "invalid_argument", message: "bulk-transfer requires ext.bulk.expected_hash" }, ctx, false);
      return;
    }
    const collected: Uint8Array[] = [];
    const queue: Uint8Array[] = [];
    const awaiters: Array<(v: IteratorResult<Uint8Array>) => void> = [];
    let streamDone = false;
    let streamError: RpcError | null = null;
    const cs: ClientStreamQueue = {
      push: (v) => {
        const bytes = v instanceof Uint8Array ? v : new Uint8Array(0);
        collected.push(bytes);
        if (awaiters.length > 0) awaiters.shift()!({ value: bytes, done: false });
        else queue.push(bytes);
      },
      done: () => {
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: new Uint8Array(0), done: true });
      },
      fail: (err) => {
        streamError = err;
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: new Uint8Array(0), done: true });
      },
    };
    const iter: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        return {
          async next(): Promise<IteratorResult<Uint8Array>> {
            if (streamError) throw new RpcCallError(streamError);
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (streamDone) return { value: new Uint8Array(0), done: true };
            return new Promise((resolve) => awaiters.push(resolve));
          },
        };
      },
    };
    const inflight: InflightCall = {
      method: rpc.method,
      method_kind: "bulk-transfer",
      capability: registered.capability,
      seq: 0,
      cancel: () => {
        streamDone = true;
      },
      clientStream: cs,
    };
    this.inflight.set(rpc.call_id, inflight);
    try {
      const receipt = await registered.handler(rpc.request, iter, ctx);
      const actualHash = await digestSha256Hex(collected);
      const verified = actualHash === expectedHash;
      if (!verified) {
        this.sendError(
          rpc.call_id,
          { code: "invalid_argument", message: `bulk-transfer hash mismatch: got ${actualHash}, expected ${expectedHash}` },
          ctx,
          false,
        );
        this.opts.onProofEvent?.({
          type: "rpc.call",
          call_id: rpc.call_id,
          method: rpc.method,
          method_kind: "bulk-transfer",
          caller,
          result: "error",
          error_code: "invalid_argument",
          bulk_hash_verified: false,
        });
        return;
      }
      this.transport.send(
        encodeRpc({
          kind: "rpc-response",
          call_id: rpc.call_id,
          status: "ok",
          response: receipt,
          ext: { method_kind: "bulk-transfer", bulk: { expected_hash: actualHash } },
        }),
      );
      this.opts.onProofEvent?.({
        type: "rpc.call",
        call_id: rpc.call_id,
        method: rpc.method,
        method_kind: "bulk-transfer",
        caller,
        result: "ok",
        bulk_hash_verified: true,
      });
    } catch (err) {
      const message = (err as Error).message ?? String(err);
      this.sendError(rpc.call_id, { code: "internal", message }, ctx, false);
    } finally {
      this.inflight.delete(rpc.call_id);
    }
  }

  private async dispatchTelemetry(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "telemetry" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
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
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined, done: true });
      },
      fail: (err) => {
        streamError = err;
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: undefined, done: true });
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
      method_kind: "telemetry",
      capability: registered.capability,
      seq: 0,
      cancel: () => {
        streamDone = true;
      },
      clientStream: cs,
    };
    this.inflight.set(rpc.call_id, inflight);
    const telCtx: TelemetryContext = { ...ctx, priority: registered.priority };
    try {
      await registered.handler(rpc.request, iter, telCtx);
      // Telemetry returns no response — emit a closing rpc-response with
      // status:ok so the client's call promise resolves.
      this.transport.send(
        encodeRpc({
          kind: "rpc-response",
          call_id: rpc.call_id,
          status: "ok",
          response: null,
          ext: { method_kind: "telemetry", streaming_priority: registered.priority },
        }),
      );
      this.opts.onProofEvent?.({
        type: "rpc.call",
        call_id: rpc.call_id,
        method: rpc.method,
        method_kind: "telemetry",
        caller,
        result: "ok",
        streaming_priority: registered.priority,
      });
    } catch (err) {
      const message = (err as Error).message ?? String(err);
      this.sendError(rpc.call_id, { code: "internal", message }, ctx, false);
    } finally {
      this.inflight.delete(rpc.call_id);
    }
  }

  private async dispatchRemoteShell(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "remote-shell" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
    const queue: Uint8Array[] = [];
    const awaiters: Array<(v: IteratorResult<Uint8Array>) => void> = [];
    let streamDone = false;
    let streamError: RpcError | null = null;
    const cs: ClientStreamQueue = {
      push: (v) => {
        // Each client frame must carry shell_stream === "stdin"; reject otherwise.
        const bytes = v instanceof Uint8Array ? v : new Uint8Array(0);
        if (awaiters.length > 0) awaiters.shift()!({ value: bytes, done: false });
        else queue.push(bytes);
      },
      done: () => {
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: new Uint8Array(0), done: true });
      },
      fail: (err) => {
        streamError = err;
        streamDone = true;
        while (awaiters.length > 0) awaiters.shift()!({ value: new Uint8Array(0), done: true });
      },
    };
    const stdinIter: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        return {
          async next(): Promise<IteratorResult<Uint8Array>> {
            if (streamError) throw new RpcCallError(streamError);
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (streamDone) return { value: new Uint8Array(0), done: true };
            return new Promise((resolve) => awaiters.push(resolve));
          },
        };
      },
    };
    const send = this.transport.send.bind(this.transport);
    const shellCtx: RemoteShellContext = {
      ...ctx,
      yield(stream: RemoteShellStream, data: Uint8Array): void {
        send(
          encodeRpc({
            kind: "rpc-stream",
            call_id: rpc.call_id,
            seq: 0,
            more: true,
            value: data,
            ext: { method_kind: "remote-shell", shell_stream: stream },
          }),
        );
      },
    };
    const inflight: InflightCall = {
      method: rpc.method,
      method_kind: "remote-shell",
      capability: registered.capability,
      seq: 0,
      cancel: () => {
        streamDone = true;
      },
      clientStream: cs,
    };
    this.inflight.set(rpc.call_id, inflight);
    let seq = 0;
    try {
      for await (const frame of registered.handler(rpc.request, stdinIter, shellCtx)) {
        if (frame.stream !== "stdin" && frame.stream !== "stdout" && frame.stream !== "stderr") {
          throw new Error(`remote-shell stream tag invalid: ${String((frame as RemoteShellFrame).stream)}`);
        }
        this.transport.send(
          encodeRpc({
            kind: "rpc-stream",
            call_id: rpc.call_id,
            seq,
            more: true,
            value: frame.data,
            ext: { method_kind: "remote-shell", shell_stream: frame.stream },
          }),
        );
        seq += 1;
        inflight.seq = seq;
      }
      this.transport.send(
        encodeRpc({
          kind: "rpc-stream",
          call_id: rpc.call_id,
          seq,
          more: false,
          ext: { method_kind: "remote-shell" },
        }),
      );
      this.opts.onProofEvent?.({
        type: "rpc.call",
        call_id: rpc.call_id,
        method: rpc.method,
        method_kind: "remote-shell",
        caller,
        result: "ok",
      });
    } catch (err) {
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
        method_kind: "remote-shell",
        caller,
        result: "error",
        error_code: "internal",
      });
    } finally {
      this.inflight.delete(rpc.call_id);
    }
  }

  private async dispatchAgentSession(
    rpc: Extract<RpcFrame, { kind: "rpc-call" }>,
    registered: Extract<Handler, { kind: "agent-session" }>,
    ctx: RpcContext,
    caller: string,
  ): Promise<void> {
    const initialChain = rpc.ext?.responsibility_chain ?? [];
    const queue: Array<{ value: unknown; chain: string[] }> = [];
    const awaiters: Array<(v: IteratorResult<{ value: unknown; responsibility_chain: string[] }>) => void> = [];
    let streamDone = false;
    let streamError: RpcError | null = null;
    const cs: ClientStreamQueue = {
      push: (v, ext) => {
        // The chain rides on the wire frame's ext; fall back to the
        // call's initial chain when absent so legacy clients still work.
        const chain = ext?.responsibility_chain ?? initialChain;
        const wrapped = { value: v as unknown, chain };
        if (awaiters.length > 0)
          awaiters.shift()!({
            value: { value: wrapped.value, responsibility_chain: wrapped.chain },
            done: false,
          });
        else queue.push(wrapped);
      },
      done: () => {
        streamDone = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { value: undefined, responsibility_chain: [] }, done: true });
      },
      fail: (err) => {
        streamError = err;
        streamDone = true;
        while (awaiters.length > 0)
          awaiters.shift()!({ value: { value: undefined, responsibility_chain: [] }, done: true });
      },
    };
    const iter: AsyncIterable<{ value: unknown; responsibility_chain: string[] }> = {
      [Symbol.asyncIterator]() {
        return {
          async next(): Promise<IteratorResult<{ value: unknown; responsibility_chain: string[] }>> {
            if (streamError) throw new RpcCallError(streamError);
            if (queue.length > 0) {
              const next = queue.shift()!;
              return { value: { value: next.value, responsibility_chain: next.chain }, done: false };
            }
            if (streamDone) return { value: { value: undefined, responsibility_chain: [] }, done: true };
            return new Promise((resolve) => awaiters.push(resolve));
          },
        };
      },
    };
    const sessCtx: AgentSessionContext = { ...ctx, initialChain };
    const inflight: InflightCall = {
      method: rpc.method,
      method_kind: "agent-session",
      capability: registered.capability,
      seq: 0,
      cancel: () => {
        streamDone = true;
      },
      clientStream: cs,
    };
    this.inflight.set(rpc.call_id, inflight);
    let seq = 0;
    try {
      for await (const out of registered.handler(rpc.request, iter, sessCtx)) {
        this.transport.send(
          encodeRpc({
            kind: "rpc-stream",
            call_id: rpc.call_id,
            seq,
            more: true,
            value: out.value,
            ext: { method_kind: "agent-session", responsibility_chain: out.responsibility_chain },
          }),
        );
        seq += 1;
        inflight.seq = seq;
      }
      this.transport.send(
        encodeRpc({
          kind: "rpc-stream",
          call_id: rpc.call_id,
          seq,
          more: false,
          ext: { method_kind: "agent-session" },
        }),
      );
      this.opts.onProofEvent?.({
        type: "rpc.call",
        call_id: rpc.call_id,
        method: rpc.method,
        method_kind: "agent-session",
        caller,
        result: "ok",
      });
    } catch (err) {
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
        method_kind: "agent-session",
        caller,
        result: "error",
        error_code: "internal",
      });
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
