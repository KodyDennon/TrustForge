# TrustForge Approval Ceremony

> `$id`: `https://trustforge.io/schemas/v0/approval-ceremony.schema.json`

Discriminated record describing how an approval was (or must be) collected. TF-0004 calls for first-class ceremony types so audit logs say not just "approved" but how (passkey tap, YubiKey touch, mobile push, quorum, offline-signed packet, biometric, physical-presence attestation, time-delay).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `ceremony_version` | `"1"` | ✓ | Version of the ceremony schema itself. |
| `ceremony_id` | string (minLength: 1) | ✓ | Stable identifier emitted alongside the ApprovalResponse. |
| `request_id` | string | · | ApprovalRequest this ceremony belongs to. |
| `started_at` | [`Timestamp`](./_common.md#timestamp) | · | When the ceremony began. |
| `completed_at` | [`Timestamp`](./_common.md#timestamp) | · | When the ceremony resolved. |
| `responder` | [`ActorId`](./_common.md#actorid) | · | Actor that resolved the ceremony. |
| `kind` | `"click"` \| `"passkey"` \| `"yubikey"` \| `"mobile-push"` \| `"time-delay"` \| `"quorum"` \| `"physical-presence"` \| `"offline-signed-packet"` \| `"biometric"` | ✓ | Discriminator naming the ceremony variant. |
| `credential_id` | string (minLength: 1) | · | Passkey/WebAuthn credential identifier (base64url). |
| `rp_id` | string (minLength: 1) | · | WebAuthn relying-party identifier the credential is bound to. |
| `client_data_hash` | [`HashRef`](./_common.md#hashref) | · | Hash of the WebAuthn clientDataJSON over which the assertion was signed. |
| `signature` | string (minLength: 1) | · | Base64-encoded signature over the canonical ApprovalRequest. |
| `serial` | string | · | YubiKey serial number. |
| `challenge` | string | · | Challenge string the device signed (HOTP / OATH / OOB code). |
| `response` | string | · | Device response over the challenge. |
| `device_actor` | [`ActorId`](./_common.md#actorid) | · | Actor URI of the device that produced the proof (mobile, biometric sensor, presence sensor). |
| `delay_seconds` | integer (≥ 1) | · | Mandatory cool-down period before the ceremony can complete. |
| `earliest_completion_at` | [`Timestamp`](./_common.md#timestamp) | · | Earliest wall-clock time the ceremony may complete. |
| `min_approvers` | integer (≥ 2) | · | Minimum number of approvers required by a quorum ceremony. |
| `of` | array of [`ActorId`](./_common.md#actorid) (minItems: 2) | · | Eligible approver set for a quorum ceremony. |
| `approvers` | array of [`ActorId`](./_common.md#actorid) | · | Subset of `of` that signed approve. |
| `signatures` | array of [`SignatureEnvelope`](./_common.md#signatureenvelope) | · | Detached approver signatures over the canonical ApprovalRequest. |
| `presence_attestation` | string (minLength: 1) | · | Opaque attestation blob from the presence sensor. |
| `packet_id` | string (minLength: 1) | · | Identifier for the offline-signed packet that carried this approval. |
| `transport_hint` | `"usb"` \| `"qr-code"` \| `"serial"` \| `"lora"` \| `"file-drop"` \| `"manual"` | · | How the offline packet reached the daemon. |
| `modality` | `"fingerprint"` \| `"face"` \| `"iris"` \| `"voice"` | · | Biometric modality used for the ceremony. |
| `match_score` | number | · | Biometric match score in [0, 1]. |
