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

import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientCredentialsChecker;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * Token granter for the authorization code grant type.
 * 
 * @author Dave Syer
 * 
 */
public class AuthorizationCodeTokenGranter implements TokenGranter {

	private static final String GRANT_TYPE = "authorization_code";

	private final AuthorizationCodeServices authorizationCodeServices;

	private final ClientCredentialsChecker clientCredentialsChecker;

	private final AuthorizationServerTokenServices tokenServices;

	public AuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
			AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService) {
		this.tokenServices = tokenServices;
		this.clientCredentialsChecker = new ClientCredentialsChecker(clientDetailsService);
		this.authorizationCodeServices = authorizationCodeServices;
	}

	public OAuth2AccessToken grant(String grantType, Map<String, String> parameters, String clientId,
			Set<String> scopes) {

		if (!GRANT_TYPE.equals(grantType)) {
			return null;
		}

		String authorizationCode = parameters.get("code");
		String redirectUri = parameters.get("redirect_uri");

		if (authorizationCode == null) {
			throw new OAuth2Exception("An authorization code must be supplied.");
		}

		AuthorizationRequestHolder storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}

		AuthorizationRequest unconfirmedAuthorizationRequest = storedAuth.getAuthenticationRequest();
		if (unconfirmedAuthorizationRequest.getRedirectUri() != null
				&& !unconfirmedAuthorizationRequest.getRedirectUri().equals(redirectUri)) {
			throw new RedirectMismatchException("Redirect URI mismatch.");
		}

		if (clientId != null && !clientId.equals(unconfirmedAuthorizationRequest.getClientId())) {
			// just a sanity check.
			throw new InvalidClientException("Client ID mismatch");
		}

		// Secret is not required in the authorization request, so it won't be available
		// in the unconfirmedAuthorizationCodeAuth. We do want to check that a secret is provided
		// in the new request, but that happens elsewhere.

		// Similarly scopes are not required in the authorization request, so we don't make a comparison here, just
		// enforce validity through the ClientCredentialsChecker
		AuthorizationRequest authorizationRequest = clientCredentialsChecker.validateCredentials(grantType, clientId,
				unconfirmedAuthorizationRequest.getScope());
		if (authorizationRequest == null) {
			return null;
		}

		Authentication userAuth = storedAuth.getUserAuthentication();
		
		OAuth2AccessToken token = tokenServices.createAccessToken(new OAuth2Authentication(authorizationRequest, userAuth));
		
		tokenServices.enhanceAccessToken(token, storedAuth);
		tokenServices.finishAccessToken(token);
		
		return token;

	}

}
