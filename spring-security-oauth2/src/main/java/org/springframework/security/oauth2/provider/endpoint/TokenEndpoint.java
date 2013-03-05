/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * <p>
 * Endpoint for token requests as described in the OAuth2 spec. Clients post requests with a <code>grant_type</code>
 * parameter (e.g. "authorization_code") and other parameters as determined by the grant type. Supported grant types are
 * handled by the provided {@link #setTokenGranter(org.springframework.security.oauth2.provider.TokenGranter) token
 * granter}.
 * </p>
 * 
 * <p>
 * Clients must be authenticated using a Spring Security {@link Authentication} to access this endpoint, and the client
 * id is extracted from the authentication token. The best way to arrange this (as per the OAuth2 spec) is to use HTTP
 * basic authentication for this endpoint with standard Spring Security support.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
@FrameworkEndpoint
@RequestMapping(value = "/oauth/token")
public class TokenEndpoint extends AbstractEndpoint {

	@RequestMapping
	public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal,
			@RequestParam(value = "grant_type", required = false) String grantType,
			@RequestParam Map<String, String> parameters) {

		if (!(principal instanceof Authentication)) {
			throw new InsufficientAuthenticationException(
					"There is no client authentication. Try adding an appropriate authentication filter.");
		}

		HashMap<String, String> request = new HashMap<String, String>(parameters);
		String clientId = getClientId(principal);
		if (clientId != null) {
			request.put("client_id", clientId);
		}

		if (!StringUtils.hasText(grantType)) {
			throw new InvalidRequestException("Missing grant type");
		}

		getAuthorizationRequestManager().validateParameters(parameters,
				getClientDetailsService().loadClientByClientId(clientId));

		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
				getAuthorizationRequestManager().createAuthorizationRequest(request));
		if (isAuthCodeRequest(parameters) || isRefreshTokenRequest(parameters)) {
			// The scope was requested or determined during the authorization step
			if (!authorizationRequest.getScope().isEmpty()) {
				logger.debug("Clearing scope of incoming auth code request");
				authorizationRequest.setScope(Collections.<String> emptySet());
			}
		}
		if (isRefreshTokenRequest(parameters)) {
			// A refresh token has its own default scopes, so we should ignore any added by the factory here.
			authorizationRequest.setScope(OAuth2Utils.parseParameterList(parameters.get("scope")));
		}
		OAuth2AccessToken token = getTokenGranter().grant(grantType, authorizationRequest);
		if (token == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + grantType);
		}

		return getResponse(token);

	}

	/**
	 * @param principal the currently authentication principal
	 * @return a client id if there is one in the principal
	 */
	protected String getClientId(Principal principal) {
		Authentication client = (Authentication) principal;
		if (!client.isAuthenticated()) {
			throw new InsufficientAuthenticationException("The client is not authenticated.");
		}
		String clientId = client.getName();
		if (client instanceof OAuth2Authentication) {
			// Might be a client and user combined authentication
			clientId = ((OAuth2Authentication) client).getAuthorizationRequest().getClientId();
		}
		return clientId;
	}

	@ExceptionHandler(ClientRegistrationException.class)
	public ResponseEntity<OAuth2Exception> handleClientRegistrationException(Exception e) throws Exception {
		logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		return getExceptionTranslator().translate(new BadClientCredentialsException());
	}

	@ExceptionHandler(OAuth2Exception.class)
	public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
		logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		return getExceptionTranslator().translate(e);
	}

	private ResponseEntity<OAuth2AccessToken> getResponse(OAuth2AccessToken accessToken) {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cache-Control", "no-store");
		headers.set("Pragma", "no-cache");
		return new ResponseEntity<OAuth2AccessToken>(accessToken, headers, HttpStatus.OK);
	}

	private boolean isRefreshTokenRequest(Map<String, String> parameters) {
		return "refresh_token".equals(parameters.get("grant_type")) && parameters.get("refresh_token") != null;
	}

	private boolean isAuthCodeRequest(Map<String, String> parameters) {
		return "authorization_code".equals(parameters.get("grant_type")) && parameters.get("code") != null;
	}

}
