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

package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.List;

/**
 * Provides core OAuth consumer information.
 *
 * @author Ryan Heaton
 */
public interface ConsumerDetails extends Serializable {

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  String getConsumerKey();

  /**
   * The name of the consumer (for display purposes).
   *
   * @return The name of the consumer (for display purposes).
   */
  String getConsumerName();

  /**
   * The signature secret.
   *
   * @return The signature secret.
   */
  SignatureSecret getSignatureSecret();

  /**
   * Get the authorities that are granted to the OAuth consumer.  Not the these are NOT the authorities
   * that are granted to the consumer with a user-authorized access token. Instead, these authorities are
   * inherent to the consumer itself.
   *
   * @return The authorities.
   */
  List<GrantedAuthority> getAuthorities();
}
