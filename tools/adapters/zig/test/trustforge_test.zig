const std = @import("std");
const testing = std.testing;
const tf = @import("trustforge");
const zap = @import("trustforge_zap");

test "Decision.parse maps known values" {
    try testing.expectEqual(tf.Decision.allow, tf.Decision.parse("allow"));
    try testing.expectEqual(tf.Decision.deny, tf.Decision.parse("deny"));
    try testing.expectEqual(
        tf.Decision.@"approval-required",
        tf.Decision.parse("approval-required"),
    );
    try testing.expectEqual(tf.Decision.escalate, tf.Decision.parse("escalate"));
    try testing.expectEqual(tf.Decision.@"log-only", tf.Decision.parse("log-only"));
    try testing.expectEqual(tf.Decision.unknown, tf.Decision.parse("nope"));
}

test "buildRequestBody only emits set fields" {
    const allocator = testing.allocator;
    const body = try tf.buildRequestBody(allocator, .{
        .action = "fs.read",
    });
    defer allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "\"action\":\"fs.read\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "host_token") == null);
    try testing.expect(std.mem.indexOf(u8, body, "target") == null);
}

test "buildRequestBody includes optional fields" {
    const allocator = testing.allocator;
    const body = try tf.buildRequestBody(allocator, .{
        .action = "net.connect",
        .host_token = "abc",
        .host_token_kind = "session",
        .target = "/v1/things",
        .trace_id = "tf-1",
    });
    defer allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "\"host_token\":\"abc\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"host_token_kind\":\"session\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"target\":\"/v1/things\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"trace_id\":\"tf-1\"") != null);
}

test "buildRequestBody escapes control characters" {
    const allocator = testing.allocator;
    const body = try tf.buildRequestBody(allocator, .{
        .action = "weird\"\n\t",
    });
    defer allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\\n") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\\t") != null);
}

test "parseResponse parses an allow with danger tags" {
    const allocator = testing.allocator;
    const json_body =
        \\{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":["fs.read","sensitive"]}
    ;
    var resp = try tf.parseResponse(allocator, json_body);
    defer resp.deinit(allocator);
    try testing.expectEqual(tf.Decision.allow, resp.decision);
    try testing.expectEqualStrings("ok", resp.reason);
    try testing.expectEqualStrings("p1", resp.proof_id);
    try testing.expectEqual(@as(usize, 2), resp.danger_tags.len);
    try testing.expectEqualStrings("fs.read", resp.danger_tags[0]);
}

test "parseResponse parses approval-required" {
    const allocator = testing.allocator;
    const body =
        \\{"decision":"approval-required","reason":"needs-human","proof_id":"p2","approval_id":"a-9","danger_tags":[]}
    ;
    var resp = try tf.parseResponse(allocator, body);
    defer resp.deinit(allocator);
    try testing.expectEqual(tf.Decision.@"approval-required", resp.decision);
    try testing.expect(resp.approval_id != null);
    try testing.expectEqualStrings("a-9", resp.approval_id.?);
    try testing.expectEqual(@as(usize, 0), resp.danger_tags.len);
}

test "parseResponse handles missing optional fields" {
    const allocator = testing.allocator;
    const body =
        \\{"decision":"deny","reason":"","proof_id":"p3"}
    ;
    var resp = try tf.parseResponse(allocator, body);
    defer resp.deinit(allocator);
    try testing.expectEqual(tf.Decision.deny, resp.decision);
    try testing.expect(resp.approval_id == null);
    try testing.expectEqual(@as(usize, 0), resp.danger_tags.len);
}

test "parseResponse rejects malformed JSON" {
    const allocator = testing.allocator;
    const result = tf.parseResponse(allocator, "not json");
    try testing.expectError(error.InvalidResponse, result);
}

test "extractBearer trims and is case-insensitive" {
    try testing.expectEqualStrings("abc", tf.extractBearer("Bearer abc").?);
    try testing.expectEqualStrings("xyz", tf.extractBearer("bearer xyz").?);
    try testing.expectEqualStrings("token", tf.extractBearer("Bearer  token  ").?);
    try testing.expect(tf.extractBearer("Bearer ") == null);
    try testing.expect(tf.extractBearer("Basic abc") == null);
    try testing.expect(tf.extractBearer(null) == null);
}

// Zap middleware test using a fake bridge.
const FakeReq = struct {
    headers: std.StringHashMap([]const u8),
    path: []const u8,
    method: []const u8,
    status: u16 = 200,
    out_headers: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, path: []const u8, method: []const u8) FakeReq {
        return .{
            .headers = std.StringHashMap([]const u8).init(allocator),
            .path = path,
            .method = method,
            .out_headers = std.StringHashMap([]const u8).init(allocator),
            .body = std.ArrayList(u8){},
            .allocator = allocator,
        };
    }
    pub fn deinit(self: *FakeReq) void {
        self.headers.deinit();
        self.out_headers.deinit();
        self.body.deinit(self.allocator);
    }
};

fn fake_get_header(ctx: *anyopaque, name: []const u8) ?[]const u8 {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    return r.headers.get(name);
}
fn fake_get_path(ctx: *anyopaque) []const u8 {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    return r.path;
}
fn fake_get_method(ctx: *anyopaque) []const u8 {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    return r.method;
}
fn fake_set_status(ctx: *anyopaque, s: u16) void {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    r.status = s;
}
fn fake_set_header(ctx: *anyopaque, name: []const u8, value: []const u8) void {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    r.out_headers.put(name, value) catch {};
}
fn fake_send_body(ctx: *anyopaque, body: []const u8) void {
    const r: *FakeReq = @ptrCast(@alignCast(ctx));
    r.body.appendSlice(r.allocator, body) catch {};
}

fn fakeBridge(req: *FakeReq) zap.RequestBridge {
    return .{
        .ctx = req,
        .get_header = fake_get_header,
        .get_path = fake_get_path,
        .get_method = fake_get_method,
        .set_status = fake_set_status,
        .set_header = fake_set_header,
        .send_body = fake_send_body,
    };
}

test "zap middleware: observe-only fallback when daemon unavailable" {
    const allocator = testing.allocator;
    var client = tf.Client.init(allocator, .{
        .daemon_url = "http://127.0.0.1:1", // refused
        .mode = .@"observe-only",
    });
    var mw = zap.Middleware.init(allocator, &client, "fs.read");

    var req = FakeReq.init(allocator, "/x", "GET");
    defer req.deinit();
    const ok = mw.handle(fakeBridge(&req));
    try testing.expect(ok);
}

test "zap middleware: enforce returns 503 when daemon unavailable" {
    const allocator = testing.allocator;
    var client = tf.Client.init(allocator, .{
        .daemon_url = "http://127.0.0.1:1",
        .mode = .enforce,
    });
    var mw = zap.Middleware.init(allocator, &client, "fs.read");

    var req = FakeReq.init(allocator, "/x", "GET");
    defer req.deinit();
    const ok = mw.handle(fakeBridge(&req));
    try testing.expect(!ok);
    try testing.expectEqual(@as(u16, 503), req.status);
}
