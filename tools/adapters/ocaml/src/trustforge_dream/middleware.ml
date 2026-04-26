(** Dream middleware for TrustForge.

    Wraps a Dream handler with a TrustForge [/v1/decide] call and
    short-circuits the request based on the resulting decision. *)

open Trustforge

let make ?(action = "http.request") (client : Trustforge.t) :
    Dream.middleware =
 fun inner request ->
  let auth = Dream.header request "authorization" in
  let host_token = Option.bind auth Trustforge.extract_bearer in
  let trace_id = Dream.header request "x-tf-trace-id" in
  let target = Some (Dream.target request) in
  let req =
    Trustforge.make_request ?host_token ?trace_id ?target action
  in
  let%lwt result = Trustforge.decide client req in
  let cfg = Trustforge.config_of client in
  match result with
  | Error e ->
      (match cfg.mode with
       | Observe_only -> inner request
       | Enforce ->
           Dream.json
             ~status:`Service_Unavailable
             (Printf.sprintf
                "{\"error\":\"trustforge-unavailable\",\"detail\":%S}"
                (error_to_string e)))
  | Ok resp ->
      (match resp.decision with
       | Allow | Log_only -> inner request
       | Deny ->
           Dream.json ~status:`Forbidden "{\"decision\":\"deny\"}"
       | Approval_required | Escalate ->
           let response =
             Dream.response
               ~status:`Accepted
               ~headers:[ "content-type", "application/json" ]
               "{\"decision\":\"approval-required\"}"
           in
           (match resp.approval_id with
            | Some aid -> Dream.set_header response "x-tf-approval-id" aid
            | None -> ());
           Lwt.return response
       | Unknown _ ->
           Dream.json
             ~status:`Service_Unavailable
             "{\"decision\":\"unknown\"}")
