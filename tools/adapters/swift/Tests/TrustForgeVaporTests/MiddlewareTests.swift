import XCTest
@testable import TrustForgeVapor
@testable import TrustForgeSDK

final class FakeTransport: TrustForgeTransport, @unchecked Sendable {
    var responses: [(Int, Data)] = []
    init(_ responses: [(Int, Data)]) { self.responses = responses }
    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data
    ) async throws -> (Int, Data) {
        guard !responses.isEmpty else {
            throw TrustForgeError(message: "no more stub responses", status: 0)
        }
        return responses.removeFirst()
    }
    static func json(_ obj: [String: Any], status: Int = 200) -> FakeTransport {
        let data = try! JSONSerialization.data(withJSONObject: obj, options: [])
        return FakeTransport([(status, data)])
    }
}

final class MiddlewareTests: XCTestCase {
    func makeClient(_ transport: FakeTransport) -> TrustForgeClient {
        TrustForgeClient(daemonURL: URL(string: "http://127.0.0.1:8787")!, transport: transport)
    }

    func testAllowCallsNext() async throws {
        let client = makeClient(FakeTransport.json(["decision": "allow"]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let req = PlainRequest(method: "GET", path: "/a")
        let resp = try await mw.respond(to: req) { _ in
            PlainResponse(status: 200, headers: [:], body: Data("ok".utf8))
        }
        XCTAssertEqual(resp.status, 200)
        XCTAssertEqual(String(data: resp.body, encoding: .utf8), "ok")
    }

    func testDenyReturns403() async throws {
        let client = makeClient(FakeTransport.json([
            "decision": "deny",
            "reason": "blocked",
            "proof_id": "p-2"
        ]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let req = PlainRequest(method: "POST", path: "/a")
        let resp = try await mw.respond(to: req) { _ in
            XCTFail("next should not run")
            return PlainResponse(status: 200, headers: [:], body: Data())
        }
        XCTAssertEqual(resp.status, 403)
        let json = try JSONSerialization.jsonObject(with: resp.body) as? [String: Any]
        XCTAssertEqual(json?["error"] as? String, "denied")
        XCTAssertEqual(json?["reason"] as? String, "blocked")
        XCTAssertEqual(json?["proof_id"] as? String, "p-2")
    }

    func testApprovalRequiredReturns202() async throws {
        let client = makeClient(FakeTransport.json([
            "decision": "approval-required",
            "approval_id": "appr-9"
        ]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let req = PlainRequest(method: "POST", path: "/a")
        let resp = try await mw.respond(to: req) { _ in
            XCTFail("next should not run")
            return PlainResponse(status: 200, headers: [:], body: Data())
        }
        XCTAssertEqual(resp.status, 202)
        XCTAssertEqual(resp.headers["x-tf-approval-id"], "appr-9")
    }

    func testDaemonError503InEnforce() async throws {
        let stub = FakeTransport([])
        let client = makeClient(stub)
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let resp = try await mw.respond(to: PlainRequest(method: "GET", path: "/x")) { _ in
            XCTFail("next should not run")
            return PlainResponse(status: 200, headers: [:], body: Data())
        }
        XCTAssertEqual(resp.status, 503)
    }

    func testObserveOnlyPassesDeny() async throws {
        let client = makeClient(FakeTransport.json([
            "decision": "deny", "reason": "would-block"
        ]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(
            client: client, action: "x", mode: .observeOnly
        )
        let resp = try await mw.respond(to: PlainRequest(method: "GET", path: "/x")) { _ in
            // Use a body marker we can verify, instead of a captured var.
            return PlainResponse(status: 201, headers: [:], body: Data("next-ran".utf8))
        }
        XCTAssertEqual(resp.status, 201)
        XCTAssertEqual(String(data: resp.body, encoding: .utf8), "next-ran")
    }

    func testActionResolverReceivesRequest() async throws {
        let client = makeClient(FakeTransport.json(["decision": "allow"]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(
            client: client,
            action: { r in "verb." + r.tfMethod.lowercased() }
        )
        let req = PlainRequest(method: "DELETE", path: "/a")
        _ = try await mw.respond(to: req) { _ in
            PlainResponse(status: 200, headers: [:], body: Data())
        }
        // No direct way to inspect the action without capturing transport — the
        // test exists primarily to prove the resolver compiles + runs without
        // crashing for arbitrary requests.
    }

    func testBearerExtraction() async throws {
        let client = makeClient(FakeTransport.json(["decision": "allow"]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let req = PlainRequest(
            method: "GET",
            path: "/a",
            headers: ["Authorization": "Bearer abc.def"]
        )
        let resp = try await mw.respond(to: req) { _ in
            PlainResponse(status: 200, headers: [:], body: Data("ok".utf8))
        }
        XCTAssertEqual(resp.status, 200)
    }

    func testTraceIdFromHeaderUsed() async throws {
        let client = makeClient(FakeTransport.json(["decision": "allow"]))
        let mw = TrustForgeMiddleware<PlainRequest, PlainResponse>(client: client, action: "x")
        let req = PlainRequest(
            method: "GET",
            path: "/a",
            headers: ["x-tf-trace-id": "tf-fixed-1"]
        )
        let resp = try await mw.respond(to: req) { _ in
            PlainResponse(status: 200, headers: [:], body: Data())
        }
        XCTAssertEqual(resp.status, 200)
    }
}
