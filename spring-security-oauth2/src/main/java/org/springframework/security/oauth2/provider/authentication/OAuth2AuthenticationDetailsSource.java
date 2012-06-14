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

package org.springframework.security.oauth2.provider.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;

/**
 * A source for authentication details in an OAuth2 protected Resource.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationDetailsSource implements
		AuthenticationDetailsSource<HttpServletRequest, OAuth2AuthenticationDetails> {

	public OAuth2AuthenticationDetails buildDetails(HttpServletRequest context) {
		return new OAuth2AuthenticationDetails(context);
	}

}
