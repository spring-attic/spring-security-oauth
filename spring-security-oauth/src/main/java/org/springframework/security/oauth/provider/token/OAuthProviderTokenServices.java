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

package org.springframework.security.oauth.provider.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public interface OAuthProviderTokenServices {

  /**
   * Read a token by its value.
   *
   * @param token The token value.
   * @return The token.
   * @throws AuthenticationException If the token is invalid, expired, or disabled.
   */
  OAuthProviderToken getToken(String token) throws AuthenticationException;

  /**
   * Create an unauthorized OAuth request token.
   *
   * @param consumerKey The consumer key for which to create the token.
   * @param callbackUrl The callback URL associated with the consumer key.
   * @return The token.
   * @throws AuthenticationException If the consumer isn't valid or otherwise isn't allowed to create a new request token.
   */
  OAuthProviderToken createUnauthorizedRequestToken(String consumerKey, String callbackUrl) throws AuthenticationException;

  /**
   * Authorize the specified request token with the specified authentication credentials. After the
   * request token is authorized, the consumer to which that request token was issued will be able
   * to use it to obtain an access token.
   *
   * @param requestToken The request token.
   * @param verifier The verifier to be assigned to the request token.
   * @param authentication The authentication credentials with which to authorize the request token. This is the
   * authentication of the <i>user</i> who has signed in and is authorizing the consumer to have access to a
   * protected resource. This same authentication can be pulled from the security context, but it's passed explicitly
   * here to suggest to the method implementation that it needs to take into account what authorities are being
   * granted to the consumer by the user.
   * @throws AuthenticationException If the token is expired or otherwise unauthorizable, or if the
   * authentication credentials are insufficient.
   */
  void authorizeRequestToken(String requestToken, String verifier, Authentication authentication) throws AuthenticationException;

  /**
   * Create an OAuth access token given the specified request token. This token will be used to provide
   * access to a protected resource. After the access token is created, the request token should be invalidated.
   *
   * @param requestToken The (presumably authorized) request token used to create the access token.
   * @return The access token.
   * @throws AuthenticationException If the request token is expired or disabled or doesn't reference the necessary authentication
   *                                 credentials or otherwise isn't authorized.
   */
  OAuthAccessProviderToken createAccessToken(String requestToken) throws AuthenticationException;

}
