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

import java.io.Serializable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * A holder of selected HTTP details related to an OAuth2 authentication request.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationDetails implements Serializable {
	
	private static final long serialVersionUID = -4809832298438307309L;

	public static final String ACCESS_TOKEN_VALUE = OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_VALUE";

	private final String remoteAddress;

	private final String sessionId;

	private final String tokenValue;

	/**
	 * Records the access token value and remote address and will also set the session Id if a session already exists
	 * (it won't create one).
	 * 
	 * @param request that the authentication request was received from
	 */
	public OAuth2AuthenticationDetails(HttpServletRequest request) {
		this.tokenValue = (String) request.getAttribute(ACCESS_TOKEN_VALUE);
		this.remoteAddress = request.getRemoteAddr();

		HttpSession session = request.getSession(false);
		this.sessionId = (session != null) ? session.getId() : null;
	}

	/**
	 * The access token value used to authenticate the request (normally in an authorization header).
	 * 
	 * @return the tokenValue used to authenticate the request
	 */
	public String getTokenValue() {
		return tokenValue;
	}

	/**
	 * Indicates the TCP/IP address the authentication request was received from.
	 * 
	 * @return the address
	 */
	public String getRemoteAddress() {
		return remoteAddress;
	}

	/**
	 * Indicates the <code>HttpSession</code> id the authentication request was received from.
	 * 
	 * @return the session ID
	 */
	public String getSessionId() {
		return sessionId;
	}

}
