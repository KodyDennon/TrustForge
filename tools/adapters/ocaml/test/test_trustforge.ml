open Trustforge

let contains haystack needle =
  let n = String.length needle in
  let h = String.length haystack in
  if n = 0 then true
  else if n > h then false
  else
    let rec loop i =
      if i + n > h then false
      else if String.sub haystack i n = needle then true
      else loop (i + 1)
    in
    loop 0

let test_decision_of_string () =
  Alcotest.(check string) "allow" "allow"
    (string_of_decision (decision_of_string "allow"));
  Alcotest.(check string) "deny" "deny"
    (string_of_decision (decision_of_string "deny"));
  Alcotest.(check string) "approval-required" "approval-required"
    (string_of_decision (decision_of_string "approval-required"));
  Alcotest.(check string) "escalate" "escalate"
    (string_of_decision (decision_of_string "escalate"));
  Alcotest.(check string) "log-only" "log-only"
    (string_of_decision (decision_of_string "log-only"));
  Alcotest.(check string) "unknown round-trip" "weird"
    (string_of_decision (decision_of_string "weird"))

let test_encode_minimal () =
  let body = encode_request_body (make_request "fs.read") in
  Alcotest.(check bool) "contains fs.read" true (contains body "fs.read");
  Alcotest.(check bool) "no host_token" false (contains body "host_token");
  Alcotest.(check bool) "no target" false (contains body "target")

let test_encode_full () =
  let body =
    encode_request_body
      (make_request
         ~host_token:"abc"
         ~host_token_kind:"session"
         ~target:"/x"
         ~trace_id:"tf-1"
         "net.connect")
  in
  Alcotest.(check bool) "host_token" true (contains body "host_token");
  Alcotest.(check bool) "host_token_kind" true (contains body "host_token_kind");
  Alcotest.(check bool) "trace_id" true (contains body "trace_id");
  Alcotest.(check bool) "target" true (contains body "target")

let test_parse_allow () =
  let body =
    "{\"decision\":\"allow\",\"reason\":\"ok\",\"proof_id\":\"p1\",\"danger_tags\":[\"fs.read\"]}"
  in
  match parse_response_body body with
  | Ok r ->
      Alcotest.(check string) "decision" "allow"
        (string_of_decision r.decision);
      Alcotest.(check string) "proof_id" "p1" r.proof_id;
      Alcotest.(check int) "tags" 1 (List.length r.danger_tags)
  | Error _ -> Alcotest.fail "expected ok"

let test_parse_approval () =
  let body =
    "{\"decision\":\"approval-required\",\"reason\":\"need\",\"proof_id\":\"p2\",\"approval_id\":\"a-9\",\"danger_tags\":[]}"
  in
  match parse_response_body body with
  | Ok r ->
      Alcotest.(check (option string)) "approval_id" (Some "a-9") r.approval_id
  | Error _ -> Alcotest.fail "expected approval-required"

let test_parse_invalid () =
  match parse_response_body "not json" with
  | Ok _ -> Alcotest.fail "expected error"
  | Error _ -> ()

let test_extract_bearer () =
  Alcotest.(check (option string)) "bearer" (Some "abc")
    (extract_bearer "Bearer abc");
  Alcotest.(check (option string)) "bearer-lc" (Some "xyz")
    (extract_bearer "bearer xyz");
  Alcotest.(check (option string)) "trim" (Some "tok")
    (extract_bearer "Bearer  tok  ");
  Alcotest.(check (option string)) "empty" None
    (extract_bearer "Bearer ");
  Alcotest.(check (option string)) "basic" None
    (extract_bearer "Basic abc")

let () =
  Alcotest.run "trustforge"
    [ ( "decisions"
      , [ Alcotest.test_case "round-trip" `Quick test_decision_of_string ] )
    ; ( "encode"
      , [ Alcotest.test_case "minimal" `Quick test_encode_minimal
        ; Alcotest.test_case "full"    `Quick test_encode_full
        ] )
    ; ( "parse"
      , [ Alcotest.test_case "allow" `Quick test_parse_allow
        ; Alcotest.test_case "approval" `Quick test_parse_approval
        ; Alcotest.test_case "invalid" `Quick test_parse_invalid
        ] )
    ; ( "bearer"
      , [ Alcotest.test_case "extract" `Quick test_extract_bearer ] )
    ]
