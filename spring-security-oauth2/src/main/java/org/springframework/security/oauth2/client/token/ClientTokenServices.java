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

package org.springframework.security.oauth2.client.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 * 
 */
public interface ClientTokenServices {

	/**
	 * Retrieve the access token for a given resource and user authentication (my be null).
	 * 
	 * @param resource the resource to be accessed
	 * @param authentication the current user authentication (or null if there is none)
	 * @return an access token if one has been stored, null otherwise
	 */
	OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication);

	/**
	 * Save or update the access token for this resource and authentication (may be null).
	 * 
	 * @param resource the resource to be accessed
	 * @param authentication the current user authentication (or null if there is none)
	 * @param accessToken an access token to be stored
	 */
	void saveAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication,
			OAuth2AccessToken accessToken);

	/**
	 * Remove the token (if any) that is stored with the provided resource and authentication. If there is no such token
	 * do nothing.
	 * 
	 * @param resource the resource to be accessed
	 * @param authentication the current user authentication (or null if there is none)
	 */
	void removeAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication);

}
