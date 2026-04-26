// TrustForgePerfect — adapter shaped to fit Perfect's `HTTPRequestFilter`
// behaviour without taking a hard SwiftPM dep on Perfect-HTTPServer.
//
// Perfect's filter contract is essentially `(request, response, callback)`
// where `callback` is one of `.continue`, `.execute`, `.halt` — modeled here as
// `TrustForgePerfectAction`. Adopting apps wrap our filter in a tiny shim that
// Perfect can install via `HTTPServer.addFilter(...)`.

import Foundation
@_exported import TrustForgeSDK

// MARK: - Bridging shapes

public protocol TrustForgePerfectRequest {
    var tfMethod: String { get }
    var tfPath: String { get }
    var tfRemoteAddress: String? { get }
    func tfHeader(_ name: String) -> String?
    func tfCookie(_ name: String) -> String?
}

/// Mutable response surface; enough to write a status, headers and body.
public protocol TrustForgePerfectResponse: AnyObject {
    func tfSet(status: Int)
    func tfAddHeader(_ name: String, _ value: String)
    func tfWrite(body: Data)
    func tfCompleted()
}

public enum TrustForgePerfectAction: Sendable, Equatable {
    /// Continue the filter chain.
    case `continue`
    /// Stop processing further filters / handlers; the response has been sent.
    case halt
}

// MARK: - Filter

public struct TrustForgePerfectFilter: Sendable {
    public typealias ActionResolver = @Sendable (any TrustForgePerfectRequest) -> String

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

    public init(client: TrustForgeClient, action: String, mode: AdapterMode = .enforce) {
        self.init(client: client, action: { _ in action }, mode: mode)
    }

    /// Run the filter against a request/response pair. Async (Perfect's API is
    /// callback-based; bridge code on the host side awaits this).
    public func filter(
        request: any TrustForgePerfectRequest,
        response: any TrustForgePerfectResponse
    ) async -> TrustForgePerfectAction {
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

        do {
            let r = try await client.decide(req)
            switch r.decision {
            case .allow, .logOnly:
                return .continue
            case .deny:
                if mode == .observeOnly { return .continue }
                writeJson(response, status: 403, body: [
                    "error": "denied",
                    "reason": r.reason,
                    "proof_id": r.proofId
                ])
                return .halt
            case .approvalRequired, .escalate:
                if mode == .observeOnly { return .continue }
                response.tfAddHeader("x-tf-approval-id", r.approvalId ?? "")
                writeJson(response, status: 202, body: [
                    "status": "approval-required",
                    "approval_id": r.approvalId ?? "",
                    "reason": r.reason
                ])
                return .halt
            }
        } catch let err as TrustForgeError {
            if mode == .observeOnly { return .continue }
            writeJson(response, status: 503, body: [
                "error": "trustforge daemon error",
                "detail": err.message
            ])
            return .halt
        } catch {
            if mode == .observeOnly { return .continue }
            writeJson(response, status: 503, body: [
                "error": "trustforge daemon error",
                "detail": "\(error)"
            ])
            return .halt
        }
    }

    private func extractToken(_ r: any TrustForgePerfectRequest) -> (String?, HostTokenKind?) {
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

    private func writeJson(
        _ response: any TrustForgePerfectResponse,
        status: Int,
        body: [String: String]
    ) {
        response.tfSet(status: status)
        response.tfAddHeader("content-type", "application/json")
        let data = (try? JSONSerialization.data(withJSONObject: body, options: [])) ?? Data()
        response.tfWrite(body: data)
        response.tfCompleted()
    }
}

// MARK: - In-package concretes for tests / non-Perfect callers

public struct PerfectPlainRequest: TrustForgePerfectRequest, Sendable {
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
        let target = name.lowercased()
        for (k, v) in headers where k.lowercased() == target { return v }
        return nil
    }
    public func tfCookie(_ name: String) -> String? { cookies[name] }
}

public final class PerfectPlainResponse: TrustForgePerfectResponse, @unchecked Sendable {
    public private(set) var status: Int = 200
    public private(set) var headers: [(String, String)] = []
    public private(set) var body: Data = Data()
    public private(set) var completed: Bool = false

    public init() {}

    public func tfSet(status: Int) { self.status = status }
    public func tfAddHeader(_ name: String, _ value: String) { headers.append((name, value)) }
    public func tfWrite(body: Data) { self.body.append(body) }
    public func tfCompleted() { completed = true }

    public func header(_ name: String) -> String? {
        let lower = name.lowercased()
        for (k, v) in headers where k.lowercased() == lower { return v }
        return nil
    }
}
