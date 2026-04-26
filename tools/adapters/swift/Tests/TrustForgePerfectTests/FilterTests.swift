import XCTest
@testable import TrustForgePerfect
@testable import TrustForgeSDK

final class StubPerfectTransport: TrustForgeTransport, @unchecked Sendable {
    var queue: [(Int, Data)]
    var failError: TrustForgeError?
    init(queue: [(Int, Data)] = [], failError: TrustForgeError? = nil) {
        self.queue = queue
        self.failError = failError
    }
    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data
    ) async throws -> (Int, Data) {
        if let err = failError { throw err }
        guard !queue.isEmpty else {
            throw TrustForgeError(message: "no responses left", status: 0)
        }
        return queue.removeFirst()
    }
    static func json(_ obj: [String: Any], status: Int = 200) -> StubPerfectTransport {
        let data = try! JSONSerialization.data(withJSONObject: obj, options: [])
        return StubPerfectTransport(queue: [(status, data)])
    }
}

final class FilterTests: XCTestCase {
    func makeClient(_ transport: TrustForgeTransport) -> TrustForgeClient {
        TrustForgeClient(daemonURL: URL(string: "http://127.0.0.1:8787")!, transport: transport)
    }

    func testAllowReturnsContinue() async {
        let client = makeClient(StubPerfectTransport.json(["decision": "allow"]))
        let f = TrustForgePerfectFilter(client: client, action: "x")
        let req = PerfectPlainRequest(method: "GET", path: "/")
        let resp = PerfectPlainResponse()
        let action = await f.filter(request: req, response: resp)
        XCTAssertEqual(action, .continue)
        XCTAssertFalse(resp.completed)
    }

    func testDenyHaltsAndWrites403() async {
        let client = makeClient(StubPerfectTransport.json([
            "decision": "deny",
            "reason": "no",
            "proof_id": "p"
        ]))
        let f = TrustForgePerfectFilter(client: client, action: "x")
        let resp = PerfectPlainResponse()
        let action = await f.filter(
            request: PerfectPlainRequest(method: "POST", path: "/x"),
            response: resp
        )
        XCTAssertEqual(action, .halt)
        XCTAssertEqual(resp.status, 403)
        XCTAssertTrue(resp.completed)
        let json = (try? JSONSerialization.jsonObject(with: resp.body)) as? [String: Any]
        XCTAssertEqual(json?["error"] as? String, "denied")
    }

    func testApprovalRequiredHaltsAndWrites202() async {
        let client = makeClient(StubPerfectTransport.json([
            "decision": "approval-required",
            "approval_id": "appr-1"
        ]))
        let f = TrustForgePerfectFilter(client: client, action: "x")
        let resp = PerfectPlainResponse()
        let action = await f.filter(
            request: PerfectPlainRequest(method: "POST", path: "/x"),
            response: resp
        )
        XCTAssertEqual(action, .halt)
        XCTAssertEqual(resp.status, 202)
        XCTAssertEqual(resp.header("x-tf-approval-id"), "appr-1")
    }

    func testDaemonError503InEnforce() async {
        let transport = StubPerfectTransport(failError: TrustForgeError(message: "boom", status: 0))
        let client = makeClient(transport)
        let f = TrustForgePerfectFilter(client: client, action: "x")
        let resp = PerfectPlainResponse()
        let action = await f.filter(
            request: PerfectPlainRequest(method: "GET", path: "/x"),
            response: resp
        )
        XCTAssertEqual(action, .halt)
        XCTAssertEqual(resp.status, 503)
    }

    func testObserveOnlyAllowsDenyAndError() async {
        // Deny should pass through
        let denyClient = makeClient(StubPerfectTransport.json(["decision": "deny"]))
        let denyF = TrustForgePerfectFilter(client: denyClient, action: "x", mode: .observeOnly)
        let denyResp = PerfectPlainResponse()
        let denyAction = await denyF.filter(
            request: PerfectPlainRequest(method: "GET", path: "/"),
            response: denyResp
        )
        XCTAssertEqual(denyAction, .continue)
        XCTAssertFalse(denyResp.completed)

        // Daemon error should pass through
        let errClient = makeClient(StubPerfectTransport(
            failError: TrustForgeError(message: "x", status: 0)
        ))
        let errF = TrustForgePerfectFilter(client: errClient, action: "x", mode: .observeOnly)
        let errResp = PerfectPlainResponse()
        let errAction = await errF.filter(
            request: PerfectPlainRequest(method: "GET", path: "/"),
            response: errResp
        )
        XCTAssertEqual(errAction, .continue)
        XCTAssertFalse(errResp.completed)
    }

    func testActionResolverReceivesRequest() async {
        let client = makeClient(StubPerfectTransport.json(["decision": "allow"]))
        let f = TrustForgePerfectFilter(
            client: client,
            action: { r in "perfect." + r.tfMethod.lowercased() }
        )
        let action = await f.filter(
            request: PerfectPlainRequest(method: "PUT", path: "/u"),
            response: PerfectPlainResponse()
        )
        XCTAssertEqual(action, .continue)
    }
}
