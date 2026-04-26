// TrustForgeVapor — middleware shaped to fit Vapor's `Middleware` protocol.
//
// We avoid taking a hard SwiftPM dep on `vapor/vapor` (multi-megabyte transitive
// graph) and instead expose a *protocol-shaped* abstraction: `TrustForgeRequest`
// and `TrustForgeResponse` mirror the parts of Vapor's request/response types
// that we actually use. Adapter consumers add a tiny bridge implementation —
// see `TrustForgeMiddleware+Vapor` in their app target — and gain TrustForge
// enforcement everywhere.
//
// The decision logic is identical to the Plug/cowboy/express adapters:
//   allow / log-only -> pass through with `tfDecision` set
//   deny             -> 403 JSON
//   approval-required / escalate -> 202 JSON with `x-tf-approval-id` header
//   daemon error in enforce mode -> 503 JSON

import Foundation
@_exported import TrustForgeSDK

// MARK: - Bridging shapes

/// Minimal request shape needed to evaluate a TrustForge decision. Vapor's
/// `Request` conforms by extension in the adopting app.
public protocol TrustForgeRequest {
    var tfMethod: String { get }
    var tfPath: String { get }
    var tfRemoteAddress: String? { get }
    func tfHeader(_ name: String) -> String?
    func tfCookie(_ name: String) -> String?
}

/// Minimal response shape returned by the middleware. Vapor's `Response`
/// conforms by extension in the adopting app.
public protocol TrustForgeResponse {
    static func tfMake(status: Int, headers: [String: String], body: Data) -> Self
}

// MARK: - Middleware

public struct TrustForgeMiddleware<Req: TrustForgeRequest, Resp: TrustForgeResponse>: Sendable {
    public typealias NextHandler = @Sendable (Req) async throws -> Resp
    public typealias ActionResolver = @Sendable (Req) -> String

    public let client: TrustForgeClient
    public let action: ActionResolver
    public let mode: AdapterMode

    public init(
        client: TrustForgeClient,
        action: @escaping ActionResolver,
        mode: AdapterMode = .enforce
    ) {
        self.client = client
        self.action = action
        self.mode = mode
    }

    /// Convenience initializer when the action is a fixed string.
    public init(client: TrustForgeClient, action: String, mode: AdapterMode = .enforce) {
        self.init(
            client: client,
            action: { _ in action },
            mode: mode
        )
    }

    public func respond(to request: Req, chainingTo next: NextHandler) async throws -> Resp {
        let traceId = request.tfHeader("x-tf-trace-id") ?? TrustForge.newTraceID()
        let (host, kind) = extractToken(request)
        let req = DecideRequest(
            action: action(request),
            traceId: traceId,
            hostToken: host,
            hostTokenKind: kind,
            target: request.tfPath,
            context: [
                "method": AnyCodable(request.tfMethod),
                "client": AnyCodable(request.tfRemoteAddress ?? "")
            ]
        )

        let result: Result<DecideResponse, TrustForgeError>
        do {
            result = .success(try await client.decide(req))
        } catch let err as TrustForgeError {
            result = .failure(err)
        } catch {
            result = .failure(TrustForgeError(message: "\(error)", status: 0))
        }

        switch result {
        case .success(let r):
            switch r.decision {
            case .allow, .logOnly:
                return try await next(request)
            case .deny:
                if mode == .observeOnly { return try await next(request) }
                return makeJson(status: 403, body: [
                    "error": "denied",
                    "reason": r.reason,
                    "proof_id": r.proofId
                ])
            case .approvalRequired, .escalate:
                if mode == .observeOnly { return try await next(request) }
                let headers = ["x-tf-approval-id": r.approvalId ?? ""]
                return makeJson(
                    status: 202,
                    headers: headers,
                    body: [
                        "status": "approval-required",
                        "approval_id": r.approvalId ?? "",
                        "reason": r.reason
                    ]
                )
            }
        case .failure(let err):
            if mode == .observeOnly { return try await next(request) }
            return makeJson(status: 503, body: [
                "error": "trustforge daemon error",
                "detail": err.message
            ])
        }
    }

    // MARK: - Internals

    private func extractToken(_ r: Req) -> (String?, HostTokenKind?) {
        if let auth = r.tfHeader("authorization") {
            let lower = auth.lowercased()
            if lower.hasPrefix("bearer ") {
                let raw = auth.dropFirst("bearer ".count)
                let tok = String(raw).trimmingCharacters(in: .whitespacesAndNewlines)
                if !tok.isEmpty { return (tok, .bearerOpaque) }
            }
        }
        if let cookie = r.tfCookie("tf_session"), !cookie.isEmpty {
            return (cookie, .sessionCookie)
        }
        return (nil, nil)
    }

    private func makeJson(
        status: Int,
        headers: [String: String] = [:],
        body: [String: String]
    ) -> Resp {
        var hdrs = headers
        hdrs["content-type"] = "application/json"
        let data = (try? JSONSerialization.data(withJSONObject: body, options: [])) ?? Data()
        return Resp.tfMake(status: status, headers: hdrs, body: data)
    }
}

// MARK: - In-package concrete response for tests / non-Vapor callers

/// Concrete `TrustForgeResponse` for tests and standalone use. In real Vapor
/// apps you'd use Vapor's `Response` and provide the conformance there.
public struct PlainResponse: TrustForgeResponse, Equatable, Sendable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data

    public init(status: Int, headers: [String: String], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    public static func tfMake(status: Int, headers: [String: String], body: Data) -> PlainResponse {
        PlainResponse(status: status, headers: headers, body: body)
    }
}

/// Concrete `TrustForgeRequest` for tests and standalone use.
public struct PlainRequest: TrustForgeRequest, Sendable {
    public let method: String
    public let path: String
    public let remote: String?
    public let headers: [String: String]
    public let cookies: [String: String]

    public init(
        method: String,
        path: String,
        remote: String? = nil,
        headers: [String: String] = [:],
        cookies: [String: String] = [:]
    ) {
        self.method = method
        self.path = path
        self.remote = remote
        self.headers = headers
        self.cookies = cookies
    }

    public var tfMethod: String { method }
    public var tfPath: String { path }
    public var tfRemoteAddress: String? { remote }
    public func tfHeader(_ name: String) -> String? {
        // case-insensitive lookup
        let target = name.lowercased()
        for (k, v) in headers where k.lowercased() == target { return v }
        return nil
    }
    public func tfCookie(_ name: String) -> String? { cookies[name] }
}
