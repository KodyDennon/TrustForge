{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Data.Aeson           as A
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text            as T
import           Test.Hspec
import           Trustforge

main :: IO ()
main = hspec $ do
  describe "parseDecision" $ do
    it "maps known decisions" $ do
      parseDecision "allow"             `shouldBe` Allow
      parseDecision "deny"              `shouldBe` Deny
      parseDecision "approval-required" `shouldBe` ApprovalRequired
      parseDecision "escalate"          `shouldBe` Escalate
      parseDecision "log-only"          `shouldBe` LogOnly
    it "preserves unknown decisions" $
      parseDecision "wat" `shouldBe` UnknownDecision "wat"
    it "round-trips through decisionToText" $
      mapM_ (\d -> parseDecision (decisionToText d) `shouldBe` d)
        [Allow, Deny, ApprovalRequired, Escalate, LogOnly]

  describe "encodeRequestBody" $ do
    it "omits unset optional fields" $ do
      let body = encodeRequestBody (emptyRequest "fs.read")
          s   = T.unpack (T.pack (show body))
      s `shouldNotContain` "host_token"
      s `shouldContain`    "fs.read"
    it "includes provided fields" $ do
      let req = (emptyRequest "net.connect")
            { reqHostToken     = Just "abc"
            , reqHostTokenKind = Just "session"
            , reqTarget        = Just "/v1/things"
            , reqTraceId       = Just "tf-1"
            }
          body = encodeRequestBody req
          s   = T.unpack (T.pack (show body))
      s `shouldContain` "host_token"
      s `shouldContain` "host_token_kind"
      s `shouldContain` "target"
      s `shouldContain` "trace_id"

  describe "parseResponseBody" $ do
    it "decodes an allow decision" $ do
      let bs = "{\"decision\":\"allow\",\"reason\":\"ok\",\"proof_id\":\"p1\",\"danger_tags\":[\"fs.read\"]}"
      case parseResponseBody (LBS.fromStrict bs) of
        Right r -> do
          respDecision   r `shouldBe` Allow
          respReason     r `shouldBe` "ok"
          respProofId    r `shouldBe` "p1"
          respApprovalId r `shouldBe` Nothing
          respDangerTags r `shouldBe` ["fs.read"]
        Left e -> expectationFailure (show e)
    it "decodes approval-required with id" $ do
      let bs = "{\"decision\":\"approval-required\",\"reason\":\"need-human\",\"proof_id\":\"p2\",\"approval_id\":\"a-9\",\"danger_tags\":[]}"
      case parseResponseBody (LBS.fromStrict bs) of
        Right r -> do
          respDecision   r `shouldBe` ApprovalRequired
          respApprovalId r `shouldBe` Just "a-9"
        Left e -> expectationFailure (show e)
    it "rejects malformed JSON" $ do
      let bs = "not json"
      case parseResponseBody bs of
        Right _                  -> expectationFailure "expected failure"
        Left (InvalidResponse _) -> pure ()
        Left other               -> expectationFailure (show other)

  describe "extractBearer" $ do
    it "matches case-insensitively" $
      extractBearer "Bearer abc" `shouldBe` Just "abc"
    it "matches lowercase" $
      extractBearer "bearer xyz" `shouldBe` Just "xyz"
    it "trims whitespace" $
      extractBearer "Bearer  token  " `shouldBe` Just "token"
    it "rejects empty token" $
      extractBearer "Bearer " `shouldBe` Nothing
    it "rejects non-bearer" $
      extractBearer "Basic abc" `shouldBe` Nothing

  describe "Config defaults" $
    it "uses 127.0.0.1:8787 as the default daemon" $
      cfgDaemonUrl defaultConfig `shouldBe` "http://127.0.0.1:8787"

  describe "ToJSON request" $
    it "renders only the action field for emptyRequest" $ do
      let body = LBS.toStrict (A.encode (emptyRequest "fs.read"))
      body `shouldBe` "{\"action\":\"fs.read\"}"
