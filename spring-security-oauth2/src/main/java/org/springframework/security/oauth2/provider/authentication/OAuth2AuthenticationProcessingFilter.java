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
package org.springframework.security.oauth2.provider.authentication;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * @author Dave Syer
 *
 */
public class OAuth2AuthenticationProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

	private final static Log logger = LogFactory.getLog(OAuth2AuthenticationProcessingFilter.class);
	
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return "N/A";
	}
	
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		return parseToken(request);
	}
	
	protected String parseToken(HttpServletRequest request) {
		// first check the header...
		String token = parseHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
		}

		return token;
	}

	/**
	 * Parse the OAuth header parameters. The parameters will be oauth-decoded.
	 * 
	 * @param request The request.
	 * @return The parsed parameters, or null if no OAuth authorization header was supplied.
	 */
	protected String parseHeaderToken(HttpServletRequest request) {
		@SuppressWarnings("unchecked")
		Enumeration<String> headers = request.getHeaders("Authorization");
		while (headers.hasMoreElements()) {
			String value = headers.nextElement();
			if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}
				return authHeaderValue;
			}
			else {
				// todo: support additional authorization schemes for different token types, e.g. "MAC" specified by
				// http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token
			}
		}

		return null;
	}

}
