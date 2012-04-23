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

package org.springframework.security.oauth2.provider.token;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Strategy for enhancing an access token before it is stored by an {@link AuthorizationServerTokenServices}
 * implementation.
 * 
 * @author Dave Syer
 * 
 */
public interface TokenEnhancer {

	/**
	 * Provides an opportunity for customization of an access token (e.g. through its additional information map) during
	 * the process of creating a new token for use by a client.
	 * 
	 * @param accessToken the current access token with its expiration and refresh token
	 * @param authentication the current authentication including client and user details
	 * @return a new token enhanced with additional information
	 */
	OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication);

}
