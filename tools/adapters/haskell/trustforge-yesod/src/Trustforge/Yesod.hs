{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE FlexibleContexts   #-}

-- |
-- Module      : Trustforge.Yesod
--
-- Yesod helpers around the core 'Trustforge' client. Two integration
-- styles are supported:
--
--   1. As a WAI middleware applied via 'yesodMiddleware' (re-exports
--      'requireAction' from 'Trustforge.Wai').
--   2. As an in-handler guard 'requireActionH' that calls @decide@ and
--      short-circuits with the appropriate HTTP status.
module Trustforge.Yesod
  ( -- * Middleware
    requireAction
  , buildDecideRequest
    -- * In-handler guard
  , requireActionH
  ) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.ByteString.Char8  as BC
import qualified Data.Text              as T
import qualified Data.Text.Encoding     as TE
import           Network.HTTP.Types     (Status, status202, status403, status503)
import           Trustforge
import           Trustforge.Wai         (buildDecideRequest, requireAction)
import qualified Yesod.Core             as Y

-- | In-handler guard. Calls @decide@ and either returns the parsed
-- response (allow / log-only) or short-circuits the handler with an
-- appropriate HTTP status.
requireActionH
  :: (Y.MonadHandler m, MonadIO m)
  => Client
  -> T.Text
  -> m DecideResponse
requireActionH client action = do
  waiReq <- Y.waiRequest
  let req = buildDecideRequest action waiReq
  result <- liftIO (decide client req)
  case result of
    Left err -> case cfgMode (clientConfig client) of
      ObserveOnly -> pure (logOnlyFallback action err)
      Enforce     -> sendShort status503 "trustforge-unavailable"
    Right resp -> case respDecision resp of
      Allow            -> pure resp
      LogOnly          -> pure resp
      Deny             -> sendShort status403 (T.pack ("deny: " <> T.unpack (respReason resp)))
      ApprovalRequired -> sendApproval resp
      Escalate         -> sendApproval resp
      UnknownDecision t ->
        sendShort status503 ("unknown decision: " <> t)
  where
    sendShort :: Y.MonadHandler m => Status -> T.Text -> m a
    sendShort s msg =
      Y.sendResponseStatus s (Y.RepPlain (Y.toContent (TE.encodeUtf8 msg)))

    sendApproval :: Y.MonadHandler m => DecideResponse -> m a
    sendApproval resp = do
      case respApprovalId resp of
        Just aid -> Y.addHeader "X-TF-Approval-Id" aid
        Nothing  -> pure ()
      Y.sendResponseStatus status202
        (Y.RepPlain (Y.toContent (BC.pack "approval-required")))

logOnlyFallback :: T.Text -> TrustforgeError -> DecideResponse
logOnlyFallback action err = DecideResponse
  { respDecision   = LogOnly
  , respReason     = "observe-only: " <> T.pack (show err)
  , respProofId    = ""
  , respApprovalId = Nothing
  , respDangerTags = [action]
  }
