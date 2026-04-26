{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE ScopedTypeVariables  #-}

-- |
-- Module      : Trustforge
--
-- Shared client for the TrustForge tf-daemon HTTP endpoint
-- @POST /v1/decide@. Designed to be used by Haskell web framework
-- adapters (WAI, Yesod, Servant, ...).
module Trustforge
  ( -- * Configuration
    Config (..)
  , defaultConfig
  , Mode (..)
    -- * Requests / responses
  , DecideRequest (..)
  , DecideResponse (..)
  , Decision (..)
  , parseDecision
  , decisionToText
  , emptyRequest
    -- * High-level API
  , Client
  , clientConfig
  , newClient
  , decide
    -- * Errors
  , TrustforgeError (..)
    -- * Helpers
  , extractBearer
  , encodeRequestBody
  , parseResponseBody
  ) where

import qualified Control.Exception          as E
import qualified Data.Aeson                 as A
import           Data.Aeson                 ((.:?), (.!=))
import qualified Data.Aeson.Types           as AT
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LBS
import qualified Data.CaseInsensitive       as CI
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE
import           GHC.Generics               (Generic)
import qualified Network.HTTP.Client        as H
import qualified Network.HTTP.Types.Method  as HM
import qualified Network.HTTP.Types.Status  as HS

-- | Enforcement mode. 'ObserveOnly' lets requests through when the
-- daemon is unreachable (logging only); 'Enforce' fails closed.
data Mode = Enforce | ObserveOnly deriving (Eq, Show)

-- | TrustForge client configuration.
data Config = Config
  { cfgDaemonUrl  :: T.Text
  , cfgAdminToken :: Maybe T.Text
  , cfgMode       :: Mode
  , cfgTimeoutMs  :: Int
  } deriving (Eq, Show)

defaultConfig :: Config
defaultConfig = Config
  { cfgDaemonUrl  = "http://127.0.0.1:8787"
  , cfgAdminToken = Nothing
  , cfgMode       = Enforce
  , cfgTimeoutMs  = 5000
  }

-- | TrustForge decision returned by the daemon.
data Decision
  = Allow
  | Deny
  | ApprovalRequired
  | Escalate
  | LogOnly
  | UnknownDecision T.Text
  deriving (Eq, Show, Generic)

decisionToText :: Decision -> T.Text
decisionToText Allow              = "allow"
decisionToText Deny               = "deny"
decisionToText ApprovalRequired   = "approval-required"
decisionToText Escalate           = "escalate"
decisionToText LogOnly            = "log-only"
decisionToText (UnknownDecision t)= t

parseDecision :: T.Text -> Decision
parseDecision t = case t of
  "allow"             -> Allow
  "deny"              -> Deny
  "approval-required" -> ApprovalRequired
  "escalate"          -> Escalate
  "log-only"          -> LogOnly
  other               -> UnknownDecision other

data DecideRequest = DecideRequest
  { reqAction        :: T.Text
  , reqHostToken     :: Maybe T.Text
  , reqHostTokenKind :: Maybe T.Text
  , reqTarget        :: Maybe T.Text
  , reqTraceId       :: Maybe T.Text
  } deriving (Eq, Show)

emptyRequest :: T.Text -> DecideRequest
emptyRequest a = DecideRequest a Nothing Nothing Nothing Nothing

instance A.ToJSON DecideRequest where
  toJSON DecideRequest{..} = A.object $
       [ "action" A..= reqAction ]
    ++ [ "host_token"      A..= v | Just v <- [reqHostToken] ]
    ++ [ "host_token_kind" A..= v | Just v <- [reqHostTokenKind] ]
    ++ [ "target"          A..= v | Just v <- [reqTarget] ]
    ++ [ "trace_id"        A..= v | Just v <- [reqTraceId] ]

data DecideResponse = DecideResponse
  { respDecision   :: Decision
  , respReason     :: T.Text
  , respProofId    :: T.Text
  , respApprovalId :: Maybe T.Text
  , respDangerTags :: [T.Text]
  } deriving (Eq, Show)

instance A.FromJSON DecideResponse where
  parseJSON = AT.withObject "DecideResponse" $ \o -> do
    decTxt <- o .:? "decision" .!= ("unknown" :: T.Text)
    DecideResponse
      <$> pure (parseDecision decTxt)
      <*> o .:? "reason"      .!= ""
      <*> o .:? "proof_id"    .!= ""
      <*> o .:? "approval_id"
      <*> o .:? "danger_tags" .!= []

data TrustforgeError
  = DaemonUnavailable String
  | DaemonRejected   Int String
  | InvalidResponse  String
  deriving (Eq, Show)

data Client = Client
  { clientCfg     :: Config
  , clientManager :: H.Manager
  }

-- | Inspect the configuration the client was created with.
clientConfig :: Client -> Config
clientConfig = clientCfg

newClient :: Config -> IO Client
newClient cfg = do
  let timeoutMicros = max 1 (cfgTimeoutMs cfg) * 1000
      ms = H.defaultManagerSettings
        { H.managerResponseTimeout = H.responseTimeoutMicro timeoutMicros }
  mgr <- H.newManager ms
  pure (Client cfg mgr)

-- | Encode a 'DecideRequest' to a strict bytestring JSON body.
encodeRequestBody :: DecideRequest -> BS.ByteString
encodeRequestBody = LBS.toStrict . A.encode

-- | Decode the daemon's response body.
parseResponseBody :: LBS.ByteString -> Either TrustforgeError DecideResponse
parseResponseBody bs = case A.eitherDecode bs of
  Left e  -> Left (InvalidResponse e)
  Right r -> Right r

decide :: Client -> DecideRequest -> IO (Either TrustforgeError DecideResponse)
decide Client{clientCfg = cfg, clientManager = mgr} req = do
  let url = T.unpack (cfgDaemonUrl cfg) <> "/v1/decide"
  case H.parseRequest url of
    Left e -> pure (Left (DaemonUnavailable (show e)))
    Right base -> do
      let bearerHeaders =
            [ (CI.mk "authorization", BC.pack ("Bearer " <> T.unpack t))
            | Just t <- [cfgAdminToken cfg] ]
          httpReq = base
            { H.method        = HM.methodPost
            , H.requestBody   = H.RequestBodyBS (encodeRequestBody req)
            , H.requestHeaders =
                (CI.mk "content-type", "application/json") : bearerHeaders
            }
      result <- (Right <$> H.httpLbs httpReq mgr) `E.catch`
                  (\(e :: H.HttpException) ->
                      pure (Left (DaemonUnavailable (show e))))
      case result of
        Left err -> pure (Left err)
        Right resp ->
          let code = HS.statusCode (H.responseStatus resp)
              body = H.responseBody resp
          in if code >= 500
               then pure (Left (DaemonUnavailable ("status " <> show code)))
               else if code >= 400
                      then pure (Left (DaemonRejected code (show body)))
                      else pure (parseResponseBody body)

-- | Pull a Bearer token out of an Authorization header value.
extractBearer :: BS.ByteString -> Maybe T.Text
extractBearer h
  | BS.length h <= 7 = Nothing
  | BC.map toLower' (BC.take 7 h) /= "bearer " = Nothing
  | otherwise =
      let raw = BC.drop 7 h
          stripped = BC.dropWhile (== ' ') (BC.reverse (BC.dropWhile (== ' ') (BC.reverse raw)))
      in if BS.null stripped
           then Nothing
           else Just (TE.decodeUtf8 stripped)
  where
    toLower' c
      | c >= 'A' && c <= 'Z' = toEnum (fromEnum c + 32)
      | otherwise            = c
