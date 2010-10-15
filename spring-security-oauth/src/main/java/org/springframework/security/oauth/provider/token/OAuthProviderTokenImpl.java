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

import org.springframework.security.core.Authentication;

/**
 * Basic implementation for an OAuth token.
 *
 * @author Ryan Heaton
 */
public class OAuthProviderTokenImpl implements OAuthAccessProviderToken {

  private static final long serialVersionUID = -1794426591002744140L;

  private String value;
  private String callbackUrl;
  private String verifier;
  private String secret;
  private String consumerKey;
  private boolean accessToken;
  private Authentication userAuthentication;
  private long timestamp;

  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  public String getValue() {
    return value;
  }

  /**
   * The value of the token.
   *
   * @param value The value of the token.
   */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  public String getSecret() {
    return secret;
  }

  /**
   * The token secret.
   *
   * @param secret The token secret.
   */
  public void setSecret(String secret) {
    this.secret = secret;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @return The consumer key associated with this oauth token.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @param consumerKey The consumer key associated with this oauth token.
   */
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  /**
   * The callback url associated with this token.
   *
   * @return The callback url associated with this token.
   */
  public String getCallbackUrl() {
    return callbackUrl;
  }

  /**
   * The callback url associated with this token.
   *
   * @param callbackUrl The callback url associated with this token.
   */
  public void setCallbackUrl(String callbackUrl) {
    this.callbackUrl = callbackUrl;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @return Whether this is an OAuth access token.
   */
  public boolean isAccessToken() {
    return accessToken;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @param accessToken Whether this is an OAuth access token.
   */
  public void setAccessToken(boolean accessToken) {
    this.accessToken = accessToken;
  }

  /**
   * The verifier string for this token.
   *
   * @return The verifier string for this token.
   */
  public String getVerifier() {
    return verifier;
  }

  /**
   * The verifier string for this (access) token.
   *
   * @param verifier The verifier string for this (access) token.
   */
  public void setVerifier(String verifier) {
    this.verifier = verifier;
  }

  /**
   * The authentication of the user who granted the access token.
   *
   * @return The authentication of the user who granted the access token.
   */
  public Authentication getUserAuthentication() {
    return userAuthentication;
  }

  /**
   * The authentication of the user who granted the access token.
   *
   * @param userAuthentication The authentication of the user who granted the access token.
   */
  public void setUserAuthentication(Authentication userAuthentication) {
    this.userAuthentication = userAuthentication;
  }

  /**
   * Timestamp associated with this token.
   *
   * @return Timestamp associated with this token.
   */
  public long getTimestamp() {
    return timestamp;
  }

  /**
   * Timestamp associated with this token.
   *
   * @param timestamp Timestamp associated with this token.
   */
  public void setTimestamp(long timestamp) {
    this.timestamp = timestamp;
  }

}
