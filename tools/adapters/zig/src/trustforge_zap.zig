//! Zap framework middleware for TrustForge.
//!
//! Wraps a Zap request handler with a TrustForge `decide` call. The
//! middleware refuses or approves the underlying handler based on the
//! returned `Decision`.
//!
//! Zap is an optional dependency: this module deliberately does not
//! `@import("zap")` so the adapter compiles without it. Users who depend
//! on Zap pass an opaque request type to `Middleware.handle` and supply
//! callbacks for reading headers / writing status codes.

const std = @import("std");
pub const tf = @import("trustforge");

/// A minimal request abstraction the middleware can talk to without
/// depending on Zap directly. Real Zap users wire these callbacks up to
/// `zap.SimpleRequest`.
pub const RequestBridge = struct {
    ctx: *anyopaque,
    get_header: *const fn (ctx: *anyopaque, name: []const u8) ?[]const u8,
    get_path: *const fn (ctx: *anyopaque) []const u8,
    get_method: *const fn (ctx: *anyopaque) []const u8,
    set_status: *const fn (ctx: *anyopaque, status: u16) void,
    set_header: *const fn (ctx: *anyopaque, name: []const u8, value: []const u8) void,
    send_body: *const fn (ctx: *anyopaque, body: []const u8) void,
};

pub const Middleware = struct {
    allocator: std.mem.Allocator,
    client: *tf.Client,
    action: []const u8,

    pub fn init(allocator: std.mem.Allocator, client: *tf.Client, action: []const u8) Middleware {
        return .{ .allocator = allocator, .client = client, .action = action };
    }

    /// Returns true when the wrapped handler should run.
    pub fn handle(self: *Middleware, bridge: RequestBridge) bool {
        const auth = bridge.get_header(bridge.ctx, "authorization");
        const host_token = tf.extractBearer(auth);
        const path = bridge.get_path(bridge.ctx);

        const trace = bridge.get_header(bridge.ctx, "x-tf-trace-id");

        const req = tf.DecideRequest{
            .action = self.action,
            .host_token = host_token,
            .target = path,
            .trace_id = trace,
        };

        var resp = self.client.decide(req) catch |err| {
            if (self.client.config.mode == .@"observe-only") return true;
            const reason = std.fmt.allocPrint(
                self.allocator,
                "{{\"error\":\"trustforge:{s}\"}}",
                .{@errorName(err)},
            ) catch return false;
            defer self.allocator.free(reason);
            bridge.set_status(bridge.ctx, 503);
            bridge.set_header(bridge.ctx, "content-type", "application/json");
            bridge.send_body(bridge.ctx, reason);
            return false;
        };
        defer resp.deinit(self.allocator);

        if (self.client.config.mode == .@"observe-only") return true;

        switch (resp.decision) {
            .allow, .@"log-only" => return true,
            .deny => {
                bridge.set_status(bridge.ctx, 403);
                bridge.set_header(bridge.ctx, "content-type", "application/json");
                bridge.send_body(bridge.ctx, "{\"decision\":\"deny\"}");
                return false;
            },
            .@"approval-required", .escalate => {
                if (resp.approval_id) |aid| bridge.set_header(bridge.ctx, "x-tf-approval-id", aid);
                bridge.set_status(bridge.ctx, 202);
                bridge.set_header(bridge.ctx, "content-type", "application/json");
                bridge.send_body(bridge.ctx, "{\"decision\":\"approval-required\"}");
                return false;
            },
            .unknown => {
                bridge.set_status(bridge.ctx, 503);
                bridge.send_body(bridge.ctx, "{\"decision\":\"unknown\"}");
                return false;
            },
        }
    }
};
