/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.client.context;

import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
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

	void setAccessToken(OAuth2AccessToken accessToken);

	void setAccessTokenRequest(AccessTokenRequest accessTokenRequest);

	/**
	 * @return the current request if any (may be null or empty)
	 */
	AccessTokenRequest getAccessTokenRequest();

	/**
	 * Convenience method for saving state in the {@link DefaultAccessTokenRequest}.
	 * 
	 * @param stateKey the key to use to save the state
	 * @param preservedState the state to be saved
	 */
	void setPreservedState(String stateKey, Object preservedState);

	/**
	 * @param stateKey the state key to lookup
	 * @return the state preserved with this key (if any)
	 */
	Object getPreservedState(String stateKey);

}