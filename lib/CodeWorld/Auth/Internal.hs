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

module CodeWorld.Auth.Internal
    ( AuthConfig
    , authenticated
    , authMethod
    , authRoutes
    , getAuthConfig
    , optionallyAuthenticated
    ) where

import           CodeWorld.Account (UserId)
import qualified CodeWorld.Auth.GoogleAuth as GoogleAuth
import           CodeWorld.Auth.Http
import qualified CodeWorld.Auth.LocalAuth as LocalAuth
import           CodeWorld.Auth.Types
import           Snap.Core (Snap, finishWith)

data AuthConfig =
    Google GoogleAuth.AuthConfig
    | Local LocalAuth.AuthConfig
    | None

getAuthConfig :: FilePath -> IO AuthConfig
getAuthConfig appDir = do
    mbLocalAuthConfig <- LocalAuth.configureAuth appDir
    case mbLocalAuthConfig of
        Just localAuthConfig -> pure $ Local localAuthConfig
        Nothing -> do
            mbGoogleAuthConfig <- GoogleAuth.configureAuth appDir
            case mbGoogleAuthConfig of
                Just googleAuthConfig -> pure $ Google googleAuthConfig
                Nothing -> pure None

authMethod :: AuthConfig -> String
authMethod (Google _) = "Google"
authMethod (Local _) = "Local"
authMethod None = "not configured"

authenticated :: (UserId -> Snap ()) -> AuthConfig -> Snap ()
authenticated handler (Local authConfig) = LocalAuth.authenticated handler authConfig
authenticated handler (Google authConfig) = GoogleAuth.authenticated handler authConfig
authenticated _ None = finishWith forbidden403

optionallyAuthenticated :: (Maybe UserId -> Snap ()) -> AuthConfig -> Snap ()
optionallyAuthenticated handler (Local authConfig) = LocalAuth.optionallyAuthenticated handler authConfig
optionallyAuthenticated handler (Google authConfig) = GoogleAuth.optionallyAuthenticated handler authConfig
optionallyAuthenticated handler None = handler Nothing

authRoutes :: AuthConfig -> [Route]
authRoutes (Google authConfig) = GoogleAuth.authRoutes authConfig
authRoutes (Local authConfig) = LocalAuth.authRoutes authConfig
authRoutes None = []
