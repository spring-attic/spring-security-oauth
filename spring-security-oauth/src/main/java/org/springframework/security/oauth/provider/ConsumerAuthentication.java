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

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Map;

/**
 * Authentication for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class ConsumerAuthentication extends AbstractAuthenticationToken {

  private final ConsumerDetails consumerDetails;
  private final ConsumerCredentials consumerCredentials;
  private final Map<String, String> oauthParameters;
  private boolean signatureValidated = false;

  public ConsumerAuthentication(ConsumerDetails consumerDetails, ConsumerCredentials consumerCredentials) {
    super(consumerDetails.getAuthorities());
    this.consumerDetails = consumerDetails;
    this.consumerCredentials = consumerCredentials;
    this.oauthParameters = null;
  }

  public ConsumerAuthentication(ConsumerDetails consumerDetails, ConsumerCredentials consumerCredentials, Map<String, String> oauthParams) {
    super(consumerDetails.getAuthorities());
    this.consumerDetails = consumerDetails;
    this.consumerCredentials = consumerCredentials;
    this.oauthParameters = oauthParams;
  }

  /**
   * The credentials.
   *
   * @return The credentials.
   * @see #getConsumerCredentials()
   */
  public Object getCredentials() {
    return getConsumerCredentials();
  }

  /**
   * The credentials of this authentication.
   *
   * @return The credentials of this authentication.
   */
  public ConsumerCredentials getConsumerCredentials() {
    return consumerCredentials;
  }

  /**
   * The principal ({@link #getConsumerDetails() consumer details}).
   *
   * @return The principal.
   * @see #getConsumerDetails()
   */
  public Object getPrincipal() {
    return getConsumerDetails();
  }

  /**
   * The consumer details.
   *
   * @return The consumer details.
   */
  public ConsumerDetails getConsumerDetails() {
    return consumerDetails;
  }

  /**
   * Get the oauth parameters supplied in the request.
   *
   * @return The oauth parameters.
   */
  public Map<String, String> getOAuthParameters() {
    return oauthParameters;
  }

  /**
   * The name of this principal is the consumer key.
   *
   * @return The name of this principal is the consumer key.
   */
  public String getName() {
    return getConsumerDetails() != null ? getConsumerDetails().getConsumerKey() : null;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  public boolean isSignatureValidated() {
    return signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @param signatureValidated Whether the signature has been validated.
   */
  public void setSignatureValidated(boolean signatureValidated) {
    this.signatureValidated = signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  @Override
  public boolean isAuthenticated() {
    return isSignatureValidated();
  }

  /**
   * Whether the signature has been validated.
   *
   * @param authenticated Whether the signature has been validated.
   */
  @Override
  public void setAuthenticated(boolean authenticated) {
    setSignatureValidated(authenticated);
  }

}
