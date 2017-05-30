/*
 * Copyright 2013-2014 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

import static org.springframework.security.oauth2.common.OAuth2AccessToken.BEARER_TYPE;
import static org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE;

/**
 * {@link TokenExtractor} that strips the authenticator from a bearer token request (with an Authorization header in the
 * form "Bearer <code>&lt;TOKEN&gt;</code>", or as a request parameter if that fails). The access token is the principal in
 * the authentication token that is extracted.
 *
 * @author Dave Syer
 *
 */
public class BearerTokenExtractor implements TokenExtractor {

	private final static Log logger = LogFactory.getLog(BearerTokenExtractor.class);

	@Override
	public Authentication extract(HttpServletRequest request) {
		String tokenValue = extractToken(request);
		if (tokenValue != null) {
			PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(tokenValue, "");
			return authentication;
		}
		return null;
	}

	protected String extractToken(HttpServletRequest request) {
		// first check the header...
		String token = extractHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
			else {
				request.setAttribute(ACCESS_TOKEN_TYPE, BEARER_TYPE);
			}
		}

		return token;
	}

	/**
	 * Extract the OAuth bearer token from a header.
	 *
	 * @param request The request.
	 * @return The token, or null if no OAuth authorization header was supplied.
	 */
	protected String extractHeaderToken(HttpServletRequest request) {
		Enumeration<String> headers = request.getHeaders("Authorization");
		// Typically there should be only one Authorization header (RFC7230, 4.2), but who knows ...
		while (headers.hasMoreElements()) {
			String value = headers.nextElement();
			final int bearerIndex = value.toLowerCase().indexOf(BEARER_TYPE.toLowerCase());

			if (bearerIndex >= 0) {
				// RFC7230 (3.2.2) allows header fields to be defined as comma-separated lists,
				// but we just care about the Bearer Token

				final int tokenIndex = bearerIndex + BEARER_TYPE.length();
				String authHeaderValue = value.substring(tokenIndex).trim();

				// Add this here for the auth details later.
				// Would be better to change the signature of this method.
				request.setAttribute(ACCESS_TOKEN_TYPE, value.substring(0, BEARER_TYPE.length()).trim());

				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}
				return authHeaderValue;
			}
		}

		return null;
	}

}
