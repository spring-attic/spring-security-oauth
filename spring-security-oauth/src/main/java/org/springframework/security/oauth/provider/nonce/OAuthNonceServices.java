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

package org.springframework.security.oauth.provider.nonce;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * @author Ryan Heaton
 */
public interface OAuthNonceServices {

  /**
   * Validate a nonce for a specific consumer timestamp. This is an opportunity to prevent replay attacks.  Every nonce
   * should be unique for each consumer timestamp. In other words, this method should throw a BadCredentialsException
   * if the specified nonce was used by the consumer more than once with the specified timestamp.
   *
   * @param consumerDetails The consumer details.
   * @param timestamp The timestamp.
   * @param nonce The nonce.
   * @throws org.springframework.security.core.AuthenticationException If the nonce failed to validate.
   */
  void validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException;
  
}
