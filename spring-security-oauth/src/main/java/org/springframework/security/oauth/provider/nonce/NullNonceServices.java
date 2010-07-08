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
 * No-op nonce services. Assumes all nonces are valid. This leaves the provider exposed to the dangers
 * of an unlimited timestamp validity window and OAuth request replay attacks.
 *
 * @author Ryan Heaton
 */
public class NullNonceServices implements OAuthNonceServices {

  public void validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    //no-op
  }
}
