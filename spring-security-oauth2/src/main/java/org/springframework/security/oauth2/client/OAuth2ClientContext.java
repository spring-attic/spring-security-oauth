/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.client;

import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 * 
 */
public interface OAuth2ClientContext {

	/**
	 * @return the current access token if any (may be null or empty)
	 */
	OAuth2AccessToken getAccessToken();

	/**
	 * @param accessToken the current access token
	 */
	void setAccessToken(OAuth2AccessToken accessToken);

	/**
	 * @return the current request if any (may be null or empty)
	 */
	AccessTokenRequest getAccessTokenRequest();

	/**
	 * Convenience method for saving state in the {@link OAuth2ClientContext}.
	 * 
	 * @param stateKey the key to use to save the state
	 * @param preservedState the state to be saved
	 */
	void setPreservedState(String stateKey, Object preservedState);

	/**
	 * @param stateKey the state key to lookup
	 * @return the state preserved with this key (if any)
	 */
	Object removePreservedState(String stateKey);

}