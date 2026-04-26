//! TrustForge shared HTTP client for Zig.
//!
//! Speaks `POST /v1/decide` against a local `tf-daemon` and returns a
//! `DecideResponse`. Network calls use `std.http.Client`.
//!
//! The client is intentionally dependency-free so that framework adapters
//! (e.g. Zap) can layer on top of it.

const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

pub const Decision = enum {
    allow,
    deny,
    @"approval-required",
    escalate,
    @"log-only",
    unknown,

    pub fn parse(s: []const u8) Decision {
        const map = .{
            .{ "allow", Decision.allow },
            .{ "deny", Decision.deny },
            .{ "approval-required", Decision.@"approval-required" },
            .{ "escalate", Decision.escalate },
            .{ "log-only", Decision.@"log-only" },
        };
        inline for (map) |kv| {
            if (std.mem.eql(u8, s, kv[0])) return kv[1];
        }
        return .unknown;
    }

    pub fn toString(self: Decision) []const u8 {
        return switch (self) {
            .allow => "allow",
            .deny => "deny",
            .@"approval-required" => "approval-required",
            .escalate => "escalate",
            .@"log-only" => "log-only",
            .unknown => "unknown",
        };
    }
};

pub const DecideRequest = struct {
    action: []const u8,
    host_token: ?[]const u8 = null,
    host_token_kind: ?[]const u8 = null,
    target: ?[]const u8 = null,
    trace_id: ?[]const u8 = null,
};

pub const DecideResponse = struct {
    decision: Decision,
    reason: []const u8,
    proof_id: []const u8,
    approval_id: ?[]const u8 = null,
    danger_tags: [][]const u8,

    /// Frees memory that this response owns. Call exactly once.
    pub fn deinit(self: *DecideResponse, allocator: Allocator) void {
        allocator.free(self.reason);
        allocator.free(self.proof_id);
        if (self.approval_id) |a| allocator.free(a);
        for (self.danger_tags) |tag| allocator.free(tag);
        allocator.free(self.danger_tags);
    }
};

pub const Mode = enum { enforce, @"observe-only" };

pub const TrustForgeError = error{
    DaemonUnavailable,
    DaemonRejected,
    InvalidResponse,
    OutOfMemory,
};

pub const Config = struct {
    daemon_url: []const u8 = "http://127.0.0.1:8787",
    admin_token: ?[]const u8 = null,
    mode: Mode = .enforce,
    timeout_ms: u32 = 5_000,
};

pub const Client = struct {
    allocator: Allocator,
    config: Config,

    pub fn init(allocator: Allocator, config: Config) Client {
        return .{ .allocator = allocator, .config = config };
    }

    /// POST /v1/decide. Caller owns the returned `DecideResponse`.
    pub fn decide(self: *Client, req: DecideRequest) TrustForgeError!DecideResponse {
        const body = try buildRequestBody(self.allocator, req);
        defer self.allocator.free(body);

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/v1/decide",
            .{self.config.daemon_url},
        );
        defer self.allocator.free(url);

        var http_client: std.http.Client = .{ .allocator = self.allocator };
        defer http_client.deinit();

        const uri = std.Uri.parse(url) catch return error.DaemonUnavailable;

        // Optional bearer header
        var auth_value_buf: ?[]u8 = null;
        defer if (auth_value_buf) |b| self.allocator.free(b);
        var extra_headers_storage: [2]std.http.Header = undefined;
        var extra_count: usize = 0;
        if (self.config.admin_token) |tok| {
            const av = std.fmt.allocPrint(
                self.allocator,
                "Bearer {s}",
                .{tok},
            ) catch return error.OutOfMemory;
            auth_value_buf = av;
            extra_headers_storage[extra_count] = .{ .name = "authorization", .value = av };
            extra_count += 1;
        }

        var response_body: std.Io.Writer.Allocating = .init(self.allocator);
        defer response_body.deinit();

        const result = http_client.fetch(.{
            .method = .POST,
            .location = .{ .uri = uri },
            .payload = body,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
            .extra_headers = extra_headers_storage[0..extra_count],
            .response_writer = &response_body.writer,
        }) catch return error.DaemonUnavailable;

        if (@intFromEnum(result.status) >= 500) return error.DaemonUnavailable;
        if (@intFromEnum(result.status) >= 400) return error.DaemonRejected;

        return parseResponse(self.allocator, response_body.written());
    }
};

/// Build a JSON request body. Caller frees.
pub fn buildRequestBody(allocator: Allocator, req: DecideRequest) TrustForgeError![]u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{");
    try writeJsonString(w, "action");
    try w.writeAll(":");
    try writeJsonString(w, req.action);

    if (req.host_token) |v| {
        try w.writeAll(",");
        try writeJsonString(w, "host_token");
        try w.writeAll(":");
        try writeJsonString(w, v);
    }
    if (req.host_token_kind) |v| {
        try w.writeAll(",");
        try writeJsonString(w, "host_token_kind");
        try w.writeAll(":");
        try writeJsonString(w, v);
    }
    if (req.target) |v| {
        try w.writeAll(",");
        try writeJsonString(w, "target");
        try w.writeAll(":");
        try writeJsonString(w, v);
    }
    if (req.trace_id) |v| {
        try w.writeAll(",");
        try writeJsonString(w, "trace_id");
        try w.writeAll(":");
        try writeJsonString(w, v);
    }
    try w.writeAll("}");

    return try buf.toOwnedSlice(allocator);
}

fn writeJsonString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => if (c < 0x20) {
                try w.print("\\u{x:0>4}", .{c});
            } else {
                try w.writeByte(c);
            },
        }
    }
    try w.writeByte('"');
}

/// Parse a `DecideResponse` JSON body. Caller owns and must `.deinit()`.
pub fn parseResponse(allocator: Allocator, body: []const u8) TrustForgeError!DecideResponse {
    var parsed = json.parseFromSlice(json.Value, allocator, body, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;
    const obj = root.object;

    const decision_str = strField(obj, "decision") orelse return error.InvalidResponse;
    const decision = Decision.parse(decision_str);

    const reason = strField(obj, "reason") orelse "";
    const proof_id = strField(obj, "proof_id") orelse "";
    const approval_id = strField(obj, "approval_id");

    var danger_tags = std.ArrayList([]const u8){};
    errdefer {
        for (danger_tags.items) |t| allocator.free(t);
        danger_tags.deinit(allocator);
    }

    if (obj.get("danger_tags")) |dt| {
        if (dt == .array) {
            for (dt.array.items) |item| {
                if (item == .string) {
                    const dup = allocator.dupe(u8, item.string) catch return error.OutOfMemory;
                    danger_tags.append(allocator, dup) catch return error.OutOfMemory;
                }
            }
        }
    }

    return DecideResponse{
        .decision = decision,
        .reason = allocator.dupe(u8, reason) catch return error.OutOfMemory,
        .proof_id = allocator.dupe(u8, proof_id) catch return error.OutOfMemory,
        .approval_id = if (approval_id) |a|
            (allocator.dupe(u8, a) catch return error.OutOfMemory)
        else
            null,
        .danger_tags = danger_tags.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

fn strField(obj: json.ObjectMap, key: []const u8) ?[]const u8 {
    if (obj.get(key)) |v| {
        if (v == .string) return v.string;
    }
    return null;
}

/// Extract a `Bearer …` token from an HTTP `Authorization` header.
pub fn extractBearer(authorization_header: ?[]const u8) ?[]const u8 {
    const h = authorization_header orelse return null;
    const prefix = "Bearer ";
    const lower_prefix = "bearer ";
    if (h.len <= prefix.len) return null;
    if (std.ascii.startsWithIgnoreCase(h, prefix) or std.ascii.startsWithIgnoreCase(h, lower_prefix)) {
        const tok = std.mem.trim(u8, h[prefix.len..], " \t");
        if (tok.len == 0) return null;
        return tok;
    }
    return null;
}
