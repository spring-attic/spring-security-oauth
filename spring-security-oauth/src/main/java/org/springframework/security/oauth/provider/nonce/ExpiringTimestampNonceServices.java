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

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * Nonce services that only validates the timestamp of a consumer request.  The nonce
 * is not checked for replay attacks. 
 *
 * The timestamp is interpreted as the number of seconds from January 1, 1970 00:00:00 GMT.  If the timestamp
 * is older than the configured validity window, the nonce is not valid. The default validity window is
 * 12 hours.
 *
 * @author Ryan Heaton
 */
public class ExpiringTimestampNonceServices implements OAuthNonceServices {

  private long validityWindowSeconds = 60 * 60 * 12; //we'll default to a 12-hour validity window.

  public void validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    long nowSeconds = (System.currentTimeMillis() / 1000);
    if ((nowSeconds - timestamp) > getValidityWindowSeconds()) {
      throw new CredentialsExpiredException("Expired timestamp.");
    }
  }

  /**
   * Set the timestamp validity window (in seconds).
   *
   * @return the timestamp validity window (in seconds).
   */
  public long getValidityWindowSeconds() {
    return validityWindowSeconds;
  }

  /**
   * The timestamp validity window (in seconds).
   *
   * @param validityWindowSeconds the timestamp validity window (in seconds).
   */
  public void setValidityWindowSeconds(long validityWindowSeconds) {
    this.validityWindowSeconds = validityWindowSeconds;
  }
}
