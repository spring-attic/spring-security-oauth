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

import java.io.Serializable;

/**
 * The credentials for an OAuth consumer request.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class ConsumerCredentials implements Serializable {

  private final String consumerKey;
  private final String signature;
  private final String signatureMethod;
  private final String signatureBaseString;
  private final String token;

  public ConsumerCredentials(String consumerKey, String signature, String signatureMethod, String signatureBaseString, String token) {
    this.signature = signature;
    this.signatureMethod = signatureMethod;
    this.signatureBaseString = signatureBaseString;
    this.consumerKey = consumerKey;
    this.token = token;
  }

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The signature.
   *
   * @return The signature.
   */
  public String getSignature() {
    return signature;
  }

  /**
   * The signature method.
   *
   * @return The signature method.
   */
  public String getSignatureMethod() {
    return signatureMethod;
  }

  /**
   * The signature base string.
   *
   * @return The signature base string.
   */
  public String getSignatureBaseString() {
    return signatureBaseString;
  }

  /**
   * The OAuth token.
   *
   * @return The OAuth token.
   */
  public String getToken() {
    return token;
  }
}
