(** TrustForge shared HTTP client for OCaml.

    Speaks [POST /v1/decide] against a local tf-daemon and returns a
    [decide_response]. Uses [Cohttp_lwt_unix] for the HTTP transport
    and [Yojson] for JSON. *)

type mode = Enforce | Observe_only

type config = {
  daemon_url : string;
  admin_token : string option;
  mode : mode;
  timeout_ms : int;
}

let default_config = {
  daemon_url = "http://127.0.0.1:8787";
  admin_token = None;
  mode = Enforce;
  timeout_ms = 5000;
}

type decision =
  | Allow
  | Deny
  | Approval_required
  | Escalate
  | Log_only
  | Unknown of string

let decision_of_string = function
  | "allow" -> Allow
  | "deny" -> Deny
  | "approval-required" -> Approval_required
  | "escalate" -> Escalate
  | "log-only" -> Log_only
  | other -> Unknown other

let string_of_decision = function
  | Allow -> "allow"
  | Deny -> "deny"
  | Approval_required -> "approval-required"
  | Escalate -> "escalate"
  | Log_only -> "log-only"
  | Unknown s -> s

type decide_request = {
  action : string;
  host_token : string option;
  host_token_kind : string option;
  target : string option;
  trace_id : string option;
}

let make_request ?host_token ?host_token_kind ?target ?trace_id action =
  { action; host_token; host_token_kind; target; trace_id }

type decide_response = {
  decision : decision;
  reason : string;
  proof_id : string;
  approval_id : string option;
  danger_tags : string list;
}

type error =
  | Daemon_unavailable of string
  | Daemon_rejected of int * string
  | Invalid_response of string

exception Trustforge_error of error

let error_to_string = function
  | Daemon_unavailable s -> Printf.sprintf "daemon-unavailable: %s" s
  | Daemon_rejected (c, s) -> Printf.sprintf "daemon-rejected[%d]: %s" c s
  | Invalid_response s -> Printf.sprintf "invalid-response: %s" s

(** Encode a [decide_request] as a JSON string body. *)
let encode_request_body req : string =
  let pairs = ref [ ("action", `String req.action) ] in
  (match req.host_token with
   | Some v -> pairs := !pairs @ [ ("host_token", `String v) ]
   | None -> ());
  (match req.host_token_kind with
   | Some v -> pairs := !pairs @ [ ("host_token_kind", `String v) ]
   | None -> ());
  (match req.target with
   | Some v -> pairs := !pairs @ [ ("target", `String v) ]
   | None -> ());
  (match req.trace_id with
   | Some v -> pairs := !pairs @ [ ("trace_id", `String v) ]
   | None -> ());
  Yojson.Safe.to_string (`Assoc !pairs)

let assoc_string key obj =
  match List.assoc_opt key obj with
  | Some (`String s) -> Some s
  | _ -> None

let assoc_string_list key obj =
  match List.assoc_opt key obj with
  | Some (`List xs) ->
      List.filter_map (function `String s -> Some s | _ -> None) xs
  | _ -> []

(** Parse a JSON response body into a [decide_response]. *)
let parse_response_body body : (decide_response, error) result =
  match Yojson.Safe.from_string body with
  | exception (Yojson.Json_error msg) -> Error (Invalid_response msg)
  | `Assoc obj ->
      let decision_str =
        Option.value (assoc_string "decision" obj) ~default:"unknown"
      in
      let reason = Option.value (assoc_string "reason" obj) ~default:"" in
      let proof_id = Option.value (assoc_string "proof_id" obj) ~default:"" in
      let approval_id = assoc_string "approval_id" obj in
      let danger_tags = assoc_string_list "danger_tags" obj in
      Ok {
        decision = decision_of_string decision_str;
        reason;
        proof_id;
        approval_id;
        danger_tags;
      }
  | _ -> Error (Invalid_response "expected JSON object")

(** Pull a Bearer token out of an Authorization header value. *)
let extract_bearer h =
  if String.length h <= 7 then None
  else
    let prefix = String.sub h 0 7 in
    let lower = String.lowercase_ascii prefix in
    if lower <> "bearer " then None
    else
      let raw = String.sub h 7 (String.length h - 7) in
      let trimmed = String.trim raw in
      if trimmed = "" then None else Some trimmed

(** Configurable client. Stores the [config] and reuses an HTTP context. *)
type t = { config : config }

let create config = { config }

let config_of t = t.config

(** Perform a [/v1/decide] call. *)
let decide (t : t) (req : decide_request) :
    (decide_response, error) result Lwt.t =
  let open Lwt.Infix in
  let body = encode_request_body req in
  let url = t.config.daemon_url ^ "/v1/decide" in
  let uri = Uri.of_string url in
  let base_headers =
    Cohttp.Header.init_with "content-type" "application/json"
  in
  let headers =
    match t.config.admin_token with
    | Some tok -> Cohttp.Header.add base_headers "authorization" ("Bearer " ^ tok)
    | None -> base_headers
  in
  Lwt.catch
    (fun () ->
      Cohttp_lwt_unix.Client.post
        ~headers
        ~body:(Cohttp_lwt.Body.of_string body)
        uri
      >>= fun (resp, body) ->
      let code = Cohttp.Code.code_of_status (Cohttp.Response.status resp) in
      Cohttp_lwt.Body.to_string body >>= fun body_str ->
      if code >= 500 then
        Lwt.return (Error (Daemon_unavailable (Printf.sprintf "status %d" code)))
      else if code >= 400 then
        Lwt.return (Error (Daemon_rejected (code, body_str)))
      else Lwt.return (parse_response_body body_str))
    (fun exn ->
      Lwt.return (Error (Daemon_unavailable (Printexc.to_string exn))))
