// TrustForgeSDK — async URLSession client for tf-daemon's `POST /v1/decide`.
//
// The wire contract is byte-compatible with the Python/TS reference clients
// (`conformance/decide-protocol-vectors.yaml`). Only `/v1/decide` is exposed;
// framework adapters (Vapor, Perfect) build on top of `TrustForgeClient`.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Wire types

public enum DecisionVerb: String, Codable, Sendable, Equatable {
    case allow
    case deny
    case escalate
    case approvalRequired = "approval-required"
    case logOnly = "log-only"
}

public enum AuthorityMode: String, Codable, Sendable, Equatable {
    case layered
    case coEqual = "co-equal"
    case replace
}

public enum HostTokenKind: String, Codable, Sendable, Equatable {
    case auto
    case oauthJwt = "oauth-jwt"
    case clerkSession = "clerk-session"
    case nextAuthJwt = "next-auth-jwt"
    case betterAuthSession = "better-auth-session"
    case webauthnAssertion = "webauthn-assertion"
    case mtlsCertPem = "mtls-cert-pem"
    case spiffeSvid = "spiffe-svid"
    case sessionCookie = "session-cookie"
    case bearerOpaque = "bearer-opaque"
}

public enum AdapterMode: String, Sendable, Equatable {
    case enforce
    case observeOnly = "observe-only"
}

public struct DecideRequest: Codable, Sendable, Equatable {
    public var actor: String?
    public var hostToken: String?
    public var hostTokenKind: HostTokenKind?
    public var action: String
    public var target: String?
    public var context: [String: AnyCodable]
    public var traceId: String

    public init(
        action: String,
        traceId: String,
        actor: String? = nil,
        hostToken: String? = nil,
        hostTokenKind: HostTokenKind? = nil,
        target: String? = nil,
        context: [String: AnyCodable] = [:]
    ) {
        self.action = action
        self.traceId = traceId
        self.actor = actor
        self.hostToken = hostToken
        self.hostTokenKind = hostTokenKind
        self.target = target
        self.context = context
    }

    private enum CodingKeys: String, CodingKey {
        case actor
        case hostToken = "host_token"
        case hostTokenKind = "host_token_kind"
        case action
        case target
        case context
        case traceId = "trace_id"
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(actor, forKey: .actor)
        try c.encodeIfPresent(hostToken, forKey: .hostToken)
        try c.encodeIfPresent(hostTokenKind, forKey: .hostTokenKind)
        try c.encode(action, forKey: .action)
        try c.encodeIfPresent(target, forKey: .target)
        try c.encode(context, forKey: .context)
        try c.encode(traceId, forKey: .traceId)
    }
}

public struct DecideResponse: Codable, Sendable, Equatable {
    public var decision: DecisionVerb
    public var reason: String
    public var approvalId: String?
    public var proofId: String
    public var actorResolved: String
    public var trustLevel: String
    public var authorityMode: AuthorityMode
    public var dangerTags: [String]

    public init(
        decision: DecisionVerb,
        reason: String = "",
        approvalId: String? = nil,
        proofId: String = "",
        actorResolved: String = "",
        trustLevel: String = "",
        authorityMode: AuthorityMode = .layered,
        dangerTags: [String] = []
    ) {
        self.decision = decision
        self.reason = reason
        self.approvalId = approvalId
        self.proofId = proofId
        self.actorResolved = actorResolved
        self.trustLevel = trustLevel
        self.authorityMode = authorityMode
        self.dangerTags = dangerTags
    }

    private enum CodingKeys: String, CodingKey {
        case decision
        case reason
        case approvalId = "approval_id"
        case proofId = "proof_id"
        case actorResolved = "actor_resolved"
        case trustLevel = "trust_level"
        case authorityMode = "authority_mode"
        case dangerTags = "danger_tags"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.decision = try c.decode(DecisionVerb.self, forKey: .decision)
        self.reason = (try? c.decode(String.self, forKey: .reason)) ?? ""
        self.approvalId = try c.decodeIfPresent(String.self, forKey: .approvalId)
        self.proofId = (try? c.decode(String.self, forKey: .proofId)) ?? ""
        self.actorResolved = (try? c.decode(String.self, forKey: .actorResolved)) ?? ""
        self.trustLevel = (try? c.decode(String.self, forKey: .trustLevel)) ?? ""
        self.authorityMode = (try? c.decode(AuthorityMode.self, forKey: .authorityMode)) ?? .layered
        self.dangerTags = (try? c.decode([String].self, forKey: .dangerTags)) ?? []
    }
}

// MARK: - Errors

public struct TrustForgeError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public let status: Int
    public let body: String?

    public init(message: String, status: Int = 0, body: String? = nil) {
        self.message = message
        self.status = status
        self.body = body
    }

    public var description: String { "TrustForgeError(status: \(status), message: \(message))" }
}

// MARK: - HTTP transport abstraction (so we can stub out URLSession in tests)

public protocol TrustForgeTransport: Sendable {
    /// Performs the HTTP request and returns `(status, body)`. Throws on
    /// network-level failure. Non-2xx statuses are surfaced through the tuple.
    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data
    ) async throws -> (Int, Data)
}

#if canImport(FoundationNetworking) || true
public struct URLSessionTransport: TrustForgeTransport {
    public let session: URLSession
    public let timeout: TimeInterval

    public init(session: URLSession = .shared, timeout: TimeInterval = 5.0) {
        self.session = session
        self.timeout = timeout
    }

    public func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data
    ) async throws -> (Int, Data) {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = timeout
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = body
        do {
            let (data, response) = try await session.data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            return (status, data)
        } catch {
            throw TrustForgeError(message: "tf-daemon network error: \(error)", status: 0)
        }
    }
}
#endif

// MARK: - Client

public actor TrustForgeClient {
    public let daemonURL: URL
    public let adminToken: String?
    public let transport: TrustForgeTransport

    public init(
        daemonURL: URL,
        adminToken: String? = nil,
        transport: TrustForgeTransport = URLSessionTransport()
    ) {
        // Strip trailing slash to keep "/v1/decide" formation deterministic.
        let s = daemonURL.absoluteString
        let trimmed: String
        if s.hasSuffix("/") {
            trimmed = String(s.dropLast())
        } else {
            trimmed = s
        }
        self.daemonURL = URL(string: trimmed) ?? daemonURL
        self.adminToken = adminToken
        self.transport = transport
    }

    public func decide(_ req: DecideRequest) async throws -> DecideResponse {
        guard let url = URL(string: self.daemonURL.absoluteString + "/v1/decide") else {
            throw TrustForgeError(message: "invalid daemon URL", status: 0)
        }
        let encoder = JSONEncoder()
        let body = try encoder.encode(req)

        var headers: [String: String] = [
            "content-type": "application/json",
            "accept": "application/json"
        ]
        if let t = adminToken, !t.isEmpty {
            headers["authorization"] = "Bearer \(t)"
        }

        let (status, data) = try await transport.send(
            url: url,
            method: "POST",
            headers: headers,
            body: body
        )
        if status >= 400 {
            let bodyString = String(data: data, encoding: .utf8)
            throw TrustForgeError(
                message: "tf-daemon /v1/decide returned \(status)",
                status: status,
                body: bodyString
            )
        }
        do {
            return try JSONDecoder().decode(DecideResponse.self, from: data)
        } catch {
            throw TrustForgeError(
                message: "tf-daemon /v1/decide JSON decode failed: \(error)",
                status: status,
                body: String(data: data, encoding: .utf8)
            )
        }
    }

    /// Convenience that maps decisions onto a Swift enum.
    public func evaluate(_ req: DecideRequest) async throws -> EvalResult {
        let r = try await decide(req)
        switch r.decision {
        case .allow: return .allow(r)
        case .deny: return .deny(r)
        case .approvalRequired, .escalate: return .approvalRequired(r)
        case .logOnly: return .logOnly(r)
        }
    }

    public enum EvalResult: Sendable {
        case allow(DecideResponse)
        case deny(DecideResponse)
        case approvalRequired(DecideResponse)
        case logOnly(DecideResponse)
    }
}

// MARK: - Helpers

public enum TrustForge {
    /// Generates a `tf-` trace id for callers that don't already have one.
    public static func newTraceID() -> String {
        var bytes = [UInt8](repeating: 0, count: 8)
        for i in 0..<bytes.count {
            bytes[i] = UInt8.random(in: 0...255)
        }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return "tf-\(hex)"
    }
}

// MARK: - AnyCodable (minimal, for context map)

public struct AnyCodable: Codable, Sendable, Equatable {
    public let value: AnyCodableValue

    public init(_ value: AnyCodableValue) { self.value = value }
    public init(_ s: String) { self.value = .string(s) }
    public init(_ i: Int) { self.value = .int(i) }
    public init(_ b: Bool) { self.value = .bool(b) }
    public init(_ d: Double) { self.value = .double(d) }
    public init(null: Void = ()) { self.value = .null }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self.value = .null }
        else if let b = try? c.decode(Bool.self) { self.value = .bool(b) }
        else if let i = try? c.decode(Int.self) { self.value = .int(i) }
        else if let d = try? c.decode(Double.self) { self.value = .double(d) }
        else if let s = try? c.decode(String.self) { self.value = .string(s) }
        else if let arr = try? c.decode([AnyCodable].self) { self.value = .array(arr) }
        else if let obj = try? c.decode([String: AnyCodable].self) { self.value = .object(obj) }
        else {
            throw DecodingError.dataCorruptedError(
                in: c, debugDescription: "unsupported AnyCodable value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

public enum AnyCodableValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([AnyCodable])
    case object([String: AnyCodable])
}
