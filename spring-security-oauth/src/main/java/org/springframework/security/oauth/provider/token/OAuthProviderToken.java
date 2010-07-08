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

import java.io.Serializable;

/**
 * @author Ryan Heaton
 */
public interface OAuthProviderToken extends Serializable {
  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  String getValue();

  /**
   * The callback URL associated with this token.
   *
   * @return The callback URL associated with this token.
   */
  String getCallbackUrl();

  /**
   * The verifier string for this token.
   *
   * @return The verifier string for this token.
   */
  String getVerifier();

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  String getSecret();

  /**
   * The consumer key associated with this oauth token.
   *
   * @return The consumer key associated with this oauth token.
   */
  String getConsumerKey();

  /**
   * Whether this is an OAuth access token.
   *
   * @return Whether this is an OAuth access token.
   */
  boolean isAccessToken();
}
