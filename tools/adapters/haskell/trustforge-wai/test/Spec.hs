{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Data.CaseInsensitive       as CI
import           Network.HTTP.Types         (status202, status403, status503)
import           Test.Hspec
import           Trustforge
import           Trustforge.Wai

main :: IO ()
main = hspec $ do
  describe "decisionResponse" $ do
    it "lets allow through (Nothing)" $ do
      let r = DecideResponse Allow "" "p" Nothing []
      decisionResponse r `shouldBe` Nothing
    it "lets log-only through" $ do
      let r = DecideResponse LogOnly "" "p" Nothing []
      decisionResponse r `shouldBe` Nothing
    it "denies with 403" $ do
      let r = DecideResponse Deny "no" "p" Nothing []
      case decisionResponse r of
        Just (s, _, _) -> s `shouldBe` status403
        Nothing        -> expectationFailure "expected deny"
    it "approval-required returns 202 + header" $ do
      let r = DecideResponse ApprovalRequired "wait" "p" (Just "a-9") []
      case decisionResponse r of
        Just (s, hs, _) -> do
          s `shouldBe` status202
          lookup (CI.mk "x-tf-approval-id") hs `shouldBe` Just "a-9"
        Nothing -> expectationFailure "expected approval"
    it "unknown decisions short-circuit with 503" $ do
      let r = DecideResponse (UnknownDecision "wat") "" "p" Nothing []
      case decisionResponse r of
        Just (s, _, _) -> s `shouldBe` status503
        Nothing        -> expectationFailure "expected unknown"
