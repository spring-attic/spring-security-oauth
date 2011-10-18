/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.token;

import java.util.Set;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Ryan Heaton
 */
public interface OAuth2ProviderTokenServices {

  /**
   * Create an access token associated with the specified credentials.
   *
   * @param authentication The credentials associated with the access token.
   * @return The access token.
   * @throws AuthenticationException If the credentials are inadequate.
   */
  OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;

  /**
   * Refresh an access token.
   *
   * @param refreshToken The details about the refresh token.
   * @param scope the scopes requested (or null or empty to use the default)
   * @return The (new) access token.
   * @throws AuthenticationException If the refresh token is invalid or expired.
   */
  OAuth2AccessToken refreshAccessToken(String refreshToken, Set<String> scope) throws AuthenticationException;
 
  /**
   * Load the credentials for the specified access token.
   *
   * @param accessToken The access token value.
   * @return The authentication for the access token.
   * @throws AuthenticationException If the access token is expired
   */
  OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException;

}