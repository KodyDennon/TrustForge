import XCTest
@testable import TrustForgeSDK

final class StubTransport: TrustForgeTransport, @unchecked Sendable {
    enum Step {
        case respond(status: Int, body: Data)
        case fail(TrustForgeError)
    }

    var step: Step
    private(set) var capturedURL: URL?
    private(set) var capturedHeaders: [String: String] = [:]
    private(set) var capturedBody: Data?
    private(set) var capturedMethod: String?

    init(_ step: Step) { self.step = step }

    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data
    ) async throws -> (Int, Data) {
        capturedURL = url
        capturedMethod = method
        capturedHeaders = headers
        capturedBody = body
        switch step {
        case .respond(let status, let body): return (status, body)
        case .fail(let err): throw err
        }
    }

    static func json(_ obj: [String: Any], status: Int = 200) -> StubTransport {
        let data = try! JSONSerialization.data(withJSONObject: obj, options: [])
        return StubTransport(.respond(status: status, body: data))
    }
}

final class ClientTests: XCTestCase {
    func makeURL() -> URL { URL(string: "http://127.0.0.1:8787/")! }

    func testDecideAllow() async throws {
        let stub = StubTransport.json([
            "decision": "allow",
            "proof_id": "p-1",
            "danger_tags": ["fs"]
        ])
        let client = TrustForgeClient(daemonURL: makeURL(), transport: stub)
        let req = DecideRequest(action: "fs.read", traceId: "tf-1")
        let resp = try await client.decide(req)
        XCTAssertEqual(resp.decision, .allow)
        XCTAssertEqual(resp.proofId, "p-1")
        XCTAssertEqual(resp.dangerTags, ["fs"])
    }

    func testDecide4xxRaises() async {
        let stub = StubTransport.json(["decision": "deny"], status: 403)
        let client = TrustForgeClient(daemonURL: makeURL(), transport: stub)
        let req = DecideRequest(action: "fs.read", traceId: "tf-1")
        do {
            _ = try await client.decide(req)
            XCTFail("expected throw")
        } catch let err as TrustForgeError {
            XCTAssertEqual(err.status, 403)
            XCTAssertTrue(err.message.contains("403"))
        } catch {
            XCTFail("wrong error type: \(error)")
        }
    }

    func testDecideNetworkErrorPropagates() async {
        let stub = StubTransport(.fail(TrustForgeError(message: "boom", status: 0)))
        let client = TrustForgeClient(daemonURL: makeURL(), transport: stub)
        do {
            _ = try await client.decide(DecideRequest(action: "x", traceId: "t"))
            XCTFail("expected throw")
        } catch let err as TrustForgeError {
            XCTAssertEqual(err.status, 0)
        } catch {
            XCTFail("wrong error type")
        }
    }

    func testRequestSerializationUsesSnakeCase() async throws {
        let stub = StubTransport.json(["decision": "allow"])
        let client = TrustForgeClient(
            daemonURL: makeURL(),
            adminToken: "ADMIN",
            transport: stub
        )
        let req = DecideRequest(
            action: "fs.read",
            traceId: "tf-xyz",
            hostToken: "abc.def",
            hostTokenKind: .oauthJwt,
            target: "/etc/hosts",
            context: ["method": AnyCodable("GET")]
        )
        _ = try await client.decide(req)
        XCTAssertEqual(stub.capturedMethod, "POST")
        XCTAssertEqual(stub.capturedURL?.absoluteString, "http://127.0.0.1:8787/v1/decide")
        XCTAssertEqual(stub.capturedHeaders["authorization"], "Bearer ADMIN")
        XCTAssertEqual(stub.capturedHeaders["content-type"], "application/json")

        guard let bodyData = stub.capturedBody else {
            XCTFail("no body captured")
            return
        }
        let any = try JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
        XCTAssertEqual(any?["action"] as? String, "fs.read")
        XCTAssertEqual(any?["trace_id"] as? String, "tf-xyz")
        XCTAssertEqual(any?["host_token"] as? String, "abc.def")
        XCTAssertEqual(any?["host_token_kind"] as? String, "oauth-jwt")
        XCTAssertEqual(any?["target"] as? String, "/etc/hosts")
        XCTAssertNil(any?["actor"])
    }

    func testEvaluateMapsAllVerbs() async throws {
        let pairs: [(String, (TrustForgeClient.EvalResult) -> Bool)] = [
            ("allow", { if case .allow = $0 { return true } else { return false } }),
            ("deny", { if case .deny = $0 { return true } else { return false } }),
            ("approval-required", { if case .approvalRequired = $0 { return true } else { return false } }),
            ("escalate", { if case .approvalRequired = $0 { return true } else { return false } }),
            ("log-only", { if case .logOnly = $0 { return true } else { return false } })
        ]
        for (verb, check) in pairs {
            let stub = StubTransport.json(["decision": verb])
            let client = TrustForgeClient(daemonURL: makeURL(), transport: stub)
            let r = try await client.evaluate(DecideRequest(action: "x", traceId: "t"))
            XCTAssertTrue(check(r), "verb \(verb) should map correctly")
        }
    }

    func testNewTraceIDFormat() {
        let id = TrustForge.newTraceID()
        XCTAssertTrue(id.hasPrefix("tf-"))
        XCTAssertEqual(id.count, 3 + 16)
    }

    func testResponseDecodingIsLenient() throws {
        // Missing optional fields should fall back to defaults.
        let json = "{\"decision\":\"allow\"}".data(using: .utf8)!
        let r = try JSONDecoder().decode(DecideResponse.self, from: json)
        XCTAssertEqual(r.decision, .allow)
        XCTAssertEqual(r.reason, "")
        XCTAssertEqual(r.proofId, "")
        XCTAssertEqual(r.authorityMode, .layered)
        XCTAssertTrue(r.dangerTags.isEmpty)
    }
}
