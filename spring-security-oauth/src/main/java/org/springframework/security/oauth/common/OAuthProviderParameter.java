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

package org.springframework.security.oauth.common;

/**
 * Parameters that can be used by the provider.
 *
 * @author Ryan Heaton
 */
public enum OAuthProviderParameter {

  /**
   * The oauth token.
   */
  oauth_token,

  /**
   * The oauth token secret.
   */
  oauth_token_secret,

  /**
   * Confirmation of the OAuth callback.
   */
  oauth_callback_confirmed,

  /**
   * Verifier
   */
  oauth_verifier
}
