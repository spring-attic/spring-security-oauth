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

package org.springframework.security.oauth.consumer.token;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;

/**
 * Token services for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public interface OAuthConsumerTokenServices {

  /**
   * Get the token for the specified protected resource.
   *
   * @param resourceId The id of the protected resource.
   * @return The token, or null if none was found.
   */
  OAuthConsumerToken getToken(String resourceId) throws AuthenticationException;

  /**
   * Store a token for a specified resource. If the token {@link OAuthConsumerToken#isAccessToken() is not an access token},
   * the token services may not have to store it and instead rely on the implementation of the
   * {@link org.springframework.security.oauth.consumer.rememberme.OAuthRememberMeServices remember-me services}. 
   *
   * @param resourceId The id of the protected resource.
   * @param token The token to store.
   */
  void storeToken(String resourceId, OAuthConsumerToken token);

  /**
   * Removes the token for the specified resource.
   *
   * @param resourceId The id of the resource.
   */
  void removeToken(String resourceId);
}
