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
 * Enumeration for consumer parameters.
 *
 * @author Ryan Heaton
 */
public enum OAuthConsumerParameter {

  /**
   * Parameter for the consumer key.
   */
  oauth_consumer_key,

  /**
   * Parameter for the oauth token.
   */
  oauth_token,

  /**
   * Parameter for the signature method.
   */
  oauth_signature_method,

  /**
   * Parameter for the signature.
   */
  oauth_signature,

  /**
   * Parameter for the timestamp.
   */
  oauth_timestamp,

  /**
   * Parameter for the nonce.
   */
  oauth_nonce,

  /**
   * Parameter for the version.
   */
  oauth_version,

  /**
   * Parameter for the callback.
   */
  oauth_callback,

  /**
   * Parameter for the verifier.
   */
  oauth_verifier

}
