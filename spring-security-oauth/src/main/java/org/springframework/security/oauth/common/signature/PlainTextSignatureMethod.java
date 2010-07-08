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

package org.springframework.security.oauth.common.signature;

import static org.springframework.security.oauth.common.OAuthCodec.*;

/**
 * Plain text signature method.
 *
 * @author Ryan Heaton
 */
public class PlainTextSignatureMethod implements OAuthSignatureMethod {

  /**
   * The name of this plain text signature method ("PLAINTEXT").
   */
  public static final String SIGNATURE_NAME = "PLAINTEXT";

  private final String secret;

  /**
   * Construct a plain text signature method with the given plain-text secret.
   *
   * @param secret The secret.
   */
  public PlainTextSignatureMethod(String secret) {
    this.secret = secret;
  }

  /**
   * The name of this plain text signature method ("PLAINTEXT").
   *
   * @return The name of this plain text signature method.
   */
  public String getName() {
    return SIGNATURE_NAME;
  }

  /**
   * The signature is the same as the secret.
   *
   * @param signatureBaseString The signature base string (unimportant, ignored).
   * @return The secret.
   */
  public String sign(String signatureBaseString) {
    return this.secret;
  }

  /**
   * Validates that the signature is the same as the secret.
   *
   * @param signatureBaseString The signature base string (unimportant, ignored).
   * @param signature The signature.
   * @throws InvalidSignatureException If the signature is not the same as the secret.
   */
  public void verify(String signatureBaseString, String signature) throws InvalidSignatureException {
    if (!signature.equals(this.secret)) {
      throw new InvalidSignatureException("Invalid signature for signature method " + getName());
    }
  }

  /**
   * The secret.
   *
   * @return The secret.
   */
  public String getSecret() {
    return secret;
  }
}
