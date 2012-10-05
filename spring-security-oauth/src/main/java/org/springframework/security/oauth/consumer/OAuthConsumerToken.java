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

package org.springframework.security.oauth.consumer;

import java.io.Serializable;
import java.util.Map;

/**
 * Interface for a consumer-side OAuth token.
 * 
 * @author Ryan Heaton
 */
public class OAuthConsumerToken implements Serializable {

  private static final long serialVersionUID = -4057986970456346647L;

  private String resourceId;
  private String value;
  private String secret;
  private boolean accessToken;
  private Map<String, String> additionalParameters;

  /**
   * The id of the resource to which this token applies.
   *
   * @return The id of the resource to which this token applies.
   */
  public String getResourceId() {
    return resourceId;
  }

  /**
   * The id of the resource to which this token applies.
   *
   * @param resourceId The id of the resource to which this token applies.
   */
  public void setResourceId(String resourceId) {
    this.resourceId = resourceId;
  }

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
   * Any additional parameters for the consumer token.
   *
   * @return Any additional parameters for the consumer token.
   */
  public Map<String, String> getAdditionalParameters() {
    return additionalParameters;
  }

  /**
   * Any additional parameters for the consumer token.
   *
   * @param additionalParameters Any additional parameters for the consumer token.
   */
  public void setAdditionalParameters(Map<String, String> additionalParameters) {
    this.additionalParameters = additionalParameters;
  }
  
  @Override
	public String toString() {
		return value;
	}
}
