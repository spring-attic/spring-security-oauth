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

import org.springframework.security.core.Authentication;

/**
 * Utility interface for converting a user authentication to and from a Map.
 * 
 * @author Dave Syer
 * 
 */
public interface UserAuthenticationConverter {

	final String AUTHORITIES = AccessTokenConverter.AUTHORITIES;

	final String USERNAME = "user_name";

	/**
	 * Extract information about the user to be used in an access token (i.e. for resource servers).
	 * 
	 * @param userAuthentication an authentication representing a user
	 * @return a map of key values representing the unique information about the user
	 */
	Map<String, ?> convertUserAuthentication(Authentication userAuthentication);

	/**
	 * Inverse of {@link #convertUserAuthentication(Authentication)}. Extracts an Authentication from a map.
	 * 
	 * @param map a map of user information
	 * @return an Authentication representing the user or null if there is none
	 */
	Authentication extractAuthentication(Map<String, ?> map);

}
