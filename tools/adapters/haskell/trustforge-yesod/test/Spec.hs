{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Test.Hspec
import           Trustforge
import           Trustforge.Yesod ()

main :: IO ()
main = hspec $ do
  describe "trustforge-yesod compiles and re-exports" $ do
    it "is wired against the shared client" $
      cfgDaemonUrl defaultConfig `shouldBe` "http://127.0.0.1:8787"
    it "knows the canonical decisions" $
      parseDecision "approval-required" `shouldBe` ApprovalRequired
