{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Trustforge.Wai
--
-- WAI middleware that calls the TrustForge daemon @/v1/decide@ endpoint
-- before letting the wrapped application handle a request. On 'Deny'
-- it returns 403, on 'ApprovalRequired' it returns 202 with an
-- @X-TF-Approval-Id@ header.
module Trustforge.Wai
  ( requireAction
  , buildDecideRequest
  , decisionResponse
  ) where

import qualified Data.ByteString            as BS
import qualified Data.CaseInsensitive       as CI
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE
import           Network.HTTP.Types         (status202, status403, status503,
                                             Status)
import qualified Network.Wai                as Wai
import           Trustforge

-- | Build a 'DecideRequest' from a WAI 'Request'.
buildDecideRequest :: T.Text -> Wai.Request -> DecideRequest
buildDecideRequest action req =
  let hdrs    = Wai.requestHeaders req
      lookup' n = lookup (CI.mk n) hdrs
      hostTok = lookup' "authorization" >>= extractBearer
      trace   = TE.decodeUtf8 <$> lookup' "x-tf-trace-id"
      target  = TE.decodeUtf8 (Wai.rawPathInfo req)
  in (emptyRequest action)
       { reqHostToken = hostTok
       , reqTraceId   = trace
       , reqTarget    = Just target
       }

-- | Wrap an 'Wai.Application' so that the named TrustForge action is
-- evaluated against the daemon before each request.
requireAction :: Client -> T.Text -> Wai.Middleware
requireAction client action app req respond = do
  let decideReq = buildDecideRequest action req
  result <- decide client decideReq
  case result of
    Left _err
      | cfgMode (clientConfig client) == ObserveOnly -> app req respond
      | otherwise ->
          respond (Wai.responseLBS status503 jsonHdr "{\"error\":\"trustforge-unavailable\"}")
    Right resp ->
      case decisionResponse resp of
        Just (status, extraHdrs, body) ->
          respond (Wai.responseLBS status (jsonHdr ++ extraHdrs) body)
        Nothing -> app req respond

-- | Map a 'DecideResponse' to an HTTP response triple, or 'Nothing'
-- if the request should be allowed through.
decisionResponse
  :: DecideResponse
  -> Maybe (Status, [(CI.CI BS.ByteString, BS.ByteString)], BS.ByteString)
decisionResponse resp = case respDecision resp of
  Allow            -> Nothing
  LogOnly          -> Nothing
  Deny             ->
    Just ( status403
         , []
         , "{\"decision\":\"deny\"}"
         )
  ApprovalRequired -> approvalResponse resp
  Escalate         -> approvalResponse resp
  UnknownDecision _ ->
    Just ( status503
         , []
         , "{\"decision\":\"unknown\"}"
         )

approvalResponse
  :: DecideResponse
  -> Maybe (Status, [(CI.CI BS.ByteString, BS.ByteString)], BS.ByteString)
approvalResponse resp =
  let hdrs = case respApprovalId resp of
        Just aid -> [(CI.mk "x-tf-approval-id", TE.encodeUtf8 aid)]
        Nothing  -> []
  in Just ( status202
         , hdrs
         , "{\"decision\":\"approval-required\"}"
         )

jsonHdr :: [(CI.CI BS.ByteString, BS.ByteString)]
jsonHdr = [(CI.mk "content-type", "application/json")]
