{-
  Copyright 2018 The CodeWorld Authors. All rights reserved.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-}

{-# LANGUAGE OverloadedStrings #-}

module CodeWorld.Auth.LocalAuth
    ( AuthConfig
    , authRoutes
    , authenticated
    , optionallyAuthenticated
    ) where

import           CodeWorld.Account
import           CodeWorld.Auth.Http
import           CodeWorld.Auth.Time
import           CodeWorld.Auth.Util
import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Class (lift)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as Char8 (pack, unpack)
import           Data.List.Split (splitOn)
import           Data.Maybe (isJust)
import           Data.Text (Text)
import qualified Data.Text as Text (pack, unpack)
import           Data.Time.Clock
                    ( NominalDiffTime
                    , UTCTime
                    , addUTCTime
                    , getCurrentTime
                    )
import           Prelude hiding (exp)
import           Snap.Core
                    ( Method(..)
                    , Snap
                    , finishWith
                    , getHeader
                    , getParam
                    , getRequest
                    , method
                    , modifyResponse
                    , pass
                    , setHeader
                    )
import           Web.JWT
                    ( Algorithm(..)
                    , JSON
                    , JWTClaimsSet(..)
                    , Secret
                    , claims
                    , decodeAndVerifySignature
                    , def
                    , encodeSigned
                    , stringOrURI
                    , stringOrURIToText
                    )

data AuthConfig = AuthConfig Secret Store

jwtIssuer :: Text
jwtIssuer = "https://code.world/"

jwtExpiryDuration :: NominalDiffTime
jwtExpiryDuration = fromInteger 5

authRoutes :: AuthConfig -> [(ByteString, Snap ())]
authRoutes authConfig =
    [ ("sign-in", method POST (signInHandler authConfig))
    ]

authenticated :: (UserId -> Snap ()) -> AuthConfig -> Snap ()
authenticated handler authConfig = do
    req <- getRequest
    case getHeader "Authorization" req of
        Nothing -> finishWith unauthorized401
        Just authHeaderBS -> authenticatedHelper authConfig handler authHeaderBS

optionallyAuthenticated :: (Maybe UserId -> Snap ()) -> AuthConfig -> Snap ()
optionallyAuthenticated handler authConfig = do
    req <- getRequest
    case getHeader "Authorization" req of
        Nothing -> handler Nothing
        Just authHeaderBS -> authenticatedHelper authConfig (\userId -> handler $ Just userId) authHeaderBS

authenticatedHelper :: AuthConfig -> (UserId -> Snap ()) -> ByteString -> Snap ()
authenticatedHelper authConfig@(AuthConfig secret_ _) handler authHeaderBS = withSnapExcept $ do
    (issuer, expiresAt, userId) <- hoistMaybe (finishWith forbidden403) $ do
        t <- parseAuthHeader authHeaderBS
        jwt <- decodeAndVerifySignature secret_ t
        let c = claims jwt
        issuer' <- iss c
        expiresAt' <- exp c
        userIdStr' <- (UserId . Text.unpack . stringOrURIToText) <$> sub c
        return (issuer', expiresAt', userIdStr')

    when
        (stringOrURIToText issuer /= jwtIssuer)
        (lift $ finishWith forbidden403)

    now <- liftIO getCurrentTime
    when
        (now >= numericDateToUTCTime expiresAt)
        (lift $ unauthorized401Json $ m [ ("reason", "token-expired") ])

    lift $ do
        handler userId
        addAuthHeader authConfig userId

authHeader :: JSON -> ByteString
authHeader t = Char8.pack $ "Bearer " ++ (Text.unpack t)

parseAuthHeader :: ByteString -> Maybe JSON
parseAuthHeader bs =
    case splitOn " " (Char8.unpack bs) of
        [authType, t] -> if authType /= "Bearer"
                            then Nothing
                            else Just (Text.pack t)
        _ -> Nothing

addAuthHeader :: AuthConfig -> UserId -> Snap ()
addAuthHeader (AuthConfig secret_ _) userId = do
    issuedAt <- liftIO getCurrentTime
    case jwtToken secret_ userId issuedAt jwtExpiryDuration of
        Nothing -> pass
        Just t -> modifyResponse $ setHeader "Authorization" (authHeader t)

jwtToken :: Secret -> UserId -> UTCTime -> NominalDiffTime -> Maybe JSON
jwtToken secret_ (UserId userIdStr) issuedAt expiryDuration = do
    let expiresAt = addUTCTime expiryDuration issuedAt
    issuedAtNum <- utcTimeToNumericDate issuedAt
    expiresAtNum <- utcTimeToNumericDate expiresAt
    let claimsSet = def
            { iss = stringOrURI jwtIssuer
            , sub = stringOrURI (Text.pack userIdStr)
            , exp = Just expiresAtNum
            , iat = Just issuedAtNum
            }
    return $ encodeSigned HS256 secret_ claimsSet

signInHandler :: AuthConfig -> Snap ()
signInHandler authConfig = do
    userId <- UserId . Char8.unpack <$> getRequiredParam "userId"
    password <- Password . Char8.unpack <$> getRequiredParam "password"
    mbNewPassword <- fmap (Password . Char8.unpack) <$> getParam "newPassword"
    case mbNewPassword of
        Nothing -> signIn authConfig userId password
        Just newPassword -> signInWithNewPassword authConfig userId password newPassword

signIn :: AuthConfig -> UserId -> Password -> Snap ()
signIn authConfig userId password
    | password == Password "expired" = unauthorized401Json $ m [ ("reason", "password-expired") ]
    | otherwise = do
                    isValid <- liftIO $ checkPassword authConfig userId password
                    case isValid of
                        False -> finishWith forbidden403
                        True -> addAuthHeader authConfig userId

signInWithNewPassword :: AuthConfig -> UserId -> Password -> Password -> Snap ()
signInWithNewPassword authConfig userId password _ = do
    isValid <- liftIO $ checkPassword authConfig userId password
    case isValid of
        False -> finishWith forbidden403
        True -> addAuthHeader authConfig userId

checkPassword :: AuthConfig -> UserId -> Password -> IO Bool
checkPassword (AuthConfig _ store) userId password = isJust <$> verifyAccount store userId password
