(** Opium middleware for TrustForge.

    Wraps an Opium handler with a TrustForge [/v1/decide] call. *)

open Trustforge
open Opium

let make ?(action = "http.request") (client : Trustforge.t) =
  let filter handler request =
    let auth = Request.header "authorization" request in
    let host_token = Option.bind auth Trustforge.extract_bearer in
    let trace_id = Request.header "x-tf-trace-id" request in
    let target = Some request.Request.target in
    let req =
      Trustforge.make_request ?host_token ?trace_id ?target action
    in
    let%lwt result = Trustforge.decide client req in
    let cfg = Trustforge.config_of client in
    match result with
    | Error e -> begin
        match cfg.mode with
        | Observe_only -> handler request
        | Enforce ->
            Lwt.return
              (Response.of_json
                 ~status:`Service_unavailable
                 (`Assoc
                   [ ("error", `String "trustforge-unavailable")
                   ; ("detail", `String (Trustforge.error_to_string e))
                   ]))
      end
    | Ok resp -> begin
        match resp.decision with
        | Allow | Log_only -> handler request
        | Deny ->
            Lwt.return
              (Response.of_json
                 ~status:`Forbidden
                 (`Assoc [ ("decision", `String "deny") ]))
        | Approval_required | Escalate ->
            let body =
              `Assoc [ ("decision", `String "approval-required") ]
            in
            let response =
              Response.of_json ~status:`Accepted body
            in
            let response =
              match resp.approval_id with
              | Some aid ->
                  Response.add_header
                    ("x-tf-approval-id", aid)
                    response
              | None -> response
            in
            Lwt.return response
        | Unknown _ ->
            Lwt.return
              (Response.of_json
                 ~status:`Service_unavailable
                 (`Assoc [ ("decision", `String "unknown") ]))
      end
  in
  Rock.Middleware.create ~name:"trustforge" ~filter
