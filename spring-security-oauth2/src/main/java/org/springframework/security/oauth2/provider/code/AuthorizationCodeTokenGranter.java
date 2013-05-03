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

package org.springframework.security.oauth2.provider.code;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * Token granter for the authorization code grant type.
 * 
 * @author Dave Syer
 * 
 */
public class AuthorizationCodeTokenGranter extends AbstractTokenGranter {

	private static final String GRANT_TYPE = "authorization_code";

	private final AuthorizationCodeServices authorizationCodeServices;

	public AuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
			AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService) {
		super(tokenServices, clientDetailsService, GRANT_TYPE);
		this.authorizationCodeServices = authorizationCodeServices;
	}

	@Override
	protected OAuth2Authentication getOAuth2Authentication(OAuth2Request oAuth2Request) {

		Map<String, String> parameters = oAuth2Request.getAuthorizationParameters();
		String authorizationCode = parameters.get("code");
		String redirectUri = parameters.get(OAuth2Request.REDIRECT_URI);

		if (authorizationCode == null) {
			throw new OAuth2Exception("An authorization code must be supplied.");
		}

		AuthorizationRequestHolder storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}

		OAuth2Request pendingOAuth2Request = storedAuth.getAuthenticationRequest();
		// https://jira.springsource.org/browse/SECOAUTH-333
		// This might be null, if the authorization was done without the redirect_uri parameter
		String redirectUriApprovalParameter = pendingOAuth2Request.getAuthorizationParameters().get(
				OAuth2Request.REDIRECT_URI);

		if ((redirectUri != null || redirectUriApprovalParameter != null)
				&& !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
			throw new RedirectMismatchException("Redirect URI mismatch.");
		}

		String pendingClientId = pendingOAuth2Request.getClientId();
		String clientId = oAuth2Request.getClientId();
		if (clientId != null && !clientId.equals(pendingClientId)) {
			// just a sanity check.
			throw new InvalidClientException("Client ID mismatch");
		}

		// Secret is not required in the authorization request, so it won't be available
		// in the pendingAuthorizationRequest. We do want to check that a secret is provided
		// in the token request, but that happens elsewhere.

		Map<String, String> combinedParameters = new HashMap<String, String>(storedAuth.getAuthenticationRequest()
				.getAuthorizationParameters());
		// Combine the parameters adding the new ones last so they override if there are any clashes
		combinedParameters.putAll(parameters);
		
		pendingOAuth2Request.setAuthorizationParameters(combinedParameters);
		
		Authentication userAuth = storedAuth.getUserAuthentication();
		return new OAuth2Authentication(pendingOAuth2Request, userAuth);

	}

}
