/*
 * Copyright 2008-2009 Web Cohesion
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

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth.common.signature.SignatureSecret;

/**
 * Base implementation for consumer details.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
@SuppressWarnings("serial")
public class BaseConsumerDetails implements ResourceSpecificConsumerDetails, ExtraTrustConsumerDetails {

  private String consumerKey;
  private String consumerName;
  private SignatureSecret signatureSecret;
  private List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
  private String resourceName;
  private String resourceDescription;
  private boolean requiredToObtainAuthenticatedToken = true;

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The consumer key.
   *
   * @param consumerKey The consumer key.
   */
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  /**
   * The name of the consumer.
   *
   * @return The name of the consumer.
   */
  public String getConsumerName() {
    return consumerName;
  }

  /**
   * The name of the consumer.
   *
   * @param consumerName The name of the consumer.
   */
  public void setConsumerName(String consumerName) {
    this.consumerName = consumerName;
  }

  /**
   * The signature secret.
   *
   * @return The signature secret.
   */
  public SignatureSecret getSignatureSecret() {
    return signatureSecret;
  }

  /**
   * The signature secret.
   *
   * @param signatureSecret The signature secret.
   */
  public void setSignatureSecret(SignatureSecret signatureSecret) {
    this.signatureSecret = signatureSecret;
  }

  /**
   * The base authorities for this consumer.
   *
   * @return The base authorities for this consumer.
   */
  public List<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  /**
   * The base authorities for this consumer.
   *
   * @param authorities The base authorities for this consumer.
   */
  public void setAuthorities(List<GrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  /**
   * The name of the resource.
   *
   * @return The name of the resource.
   */
  public String getResourceName() {
    return resourceName;
  }

  /**
   * The name of the resource.
   *
   * @param resourceName The name of the resource.
   */
  public void setResourceName(String resourceName) {
    this.resourceName = resourceName;
  }

  /**
   * The description of the resource.
   *
   * @return The description of the resource.
   */
  public String getResourceDescription() {
    return resourceDescription;
  }

  /**
   * The description of the resource.
   *
   * @param resourceDescription The description of the resource.
   */
  public void setResourceDescription(String resourceDescription) {
    this.resourceDescription = resourceDescription;
  }

  /**
   * Whether this consumer is required to obtain an authenticated oauth token.
   *
   * @return Whether this consumer is required to obtain an authenticated oauth token.
   */
  public boolean isRequiredToObtainAuthenticatedToken() {
    return requiredToObtainAuthenticatedToken;
  }

  /**
   * Whether this consumer is required to obtain an authenticated oauth token.
   *
   * @param requiredToObtainAuthenticatedToken Whether this consumer is required to obtain an authenticated oauth token.
   */
  public void setRequiredToObtainAuthenticatedToken(boolean requiredToObtainAuthenticatedToken) {
    this.requiredToObtainAuthenticatedToken = requiredToObtainAuthenticatedToken;
  }
}
