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

import java.util.Map;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Converter interface for token service implementations that store authentication data inside the token.
 * 
 * @author Dave Syer
 * 
 */
public interface AccessTokenConverter {

	final String AUD = "aud";

	final String CLIENT_ID = "client_id";

	final String EXP = "exp";

	final String JTI = "jti";
	
	final String GRANT_TYPE = "grant_type";

	final String ATI = "ati";

	final String SCOPE = OAuth2AccessToken.SCOPE;

	final String AUTHORITIES = "authorities";

	/**
	 * @param token an access token
	 * @param authentication the current OAuth authentication
	 * 
	 * @return a map representation of the token suitable for a JSON response
	 * 
	 */
	Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication);

	/**
	 * Recover an access token from the converted value. Half the inverse of
	 * {@link #convertAccessToken(OAuth2AccessToken, OAuth2Authentication)}.
	 * 
	 * @param value the token value
	 * @param map information decoded from an access token
	 * @return an access token
	 */
	OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map);

	/**
	 * Recover an {@link OAuth2Authentication} from the converted access token. Half the inverse of
	 * {@link #convertAccessToken(OAuth2AccessToken, OAuth2Authentication)}.
	 * 
	 * @param map information decoded from an access token
	 * @return an authentication representing the client and user (if there is one)
	 */
	OAuth2Authentication extractAuthentication(Map<String, ?> map);

}