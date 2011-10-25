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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.SaltedClientSecret;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * 
 */
public class AuthorizationCodeTokenGranter implements TokenGranter {

	private static final String GRANT_TYPE = "authorization_code";
	private final AuthorizationServerTokenServices tokenServices;
	private final AuthorizationCodeServices authorizationCodeServices;
	private final ClientDetailsService clientDetailsService;
	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

	public AuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
			AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService) {
		this.tokenServices = tokenServices;
		this.authorizationCodeServices = authorizationCodeServices;
		this.clientDetailsService = clientDetailsService;
	}

	public OAuth2AccessToken grant(String grantType, Map<String, String> parameters, String clientId,
			String clientSecret, Set<String> authorizationScope) {

		if (!GRANT_TYPE.equals(grantType)) {
			return null;
		}
		String authorizationCode = parameters.get("code");
		String state = parameters.get("state");
		String redirectUri = parameters.get("redirect_uri");

		if (authorizationCode == null) {
			throw new OAuth2Exception("An authorization code must be supplied.");
		}

		UnconfirmedAuthorizationCodeAuthenticationTokenHolder storedAuth = authorizationCodeServices
				.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}

		UnconfirmedAuthorizationCodeClientToken unconfirmedAuthorizationCodeAuth = storedAuth
				.getClientAuthentication();
		if (unconfirmedAuthorizationCodeAuth.getRequestedRedirect() != null
				&& !unconfirmedAuthorizationCodeAuth.getRequestedRedirect().equals(redirectUri)) {
			throw new RedirectMismatchException("Redirect URI mismatch.");
		}

		if (clientId != null && !clientId.equals(unconfirmedAuthorizationCodeAuth.getClientId())) {
			// just a sanity check.
			throw new InvalidClientException("Client ID mismatch");
		}
		// Secret is not required in the authorization request, so it won't be available
		// in the unconfirmedAuthorizationCodeAuth. We do want to check that a secret is provided
		// in the new request, but that happens elsewhere.

		if (StringUtils.hasText(state) && !state.equals(unconfirmedAuthorizationCodeAuth.getState())) {
			// just a sanity check.
			throw new InvalidRequestException("State mismatch");
		}
		if (StringUtils.hasText(unconfirmedAuthorizationCodeAuth.getState())
				&& !unconfirmedAuthorizationCodeAuth.getState().equals(state)) {
			// just a sanity check.
			throw new InvalidRequestException("State mismatch");
		}

		Set<String> unconfirmedAuthorizationScope = unconfirmedAuthorizationCodeAuth.getScope();
		if (!unconfirmedAuthorizationScope.containsAll(authorizationScope)) {
			throw new InvalidScopeException("Request for access token scope outside of authorization code scope.");
		}
		if (authorizationScope.isEmpty()) {
			authorizationScope = unconfirmedAuthorizationScope;
		}

		// TODO: move this out to a filter?
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		if (clientDetails.isSecretRequired()) {
			String assertedSecret = clientSecret;
			if (assertedSecret == null) {
				throw new UnauthorizedClientException("Client secret is required but not provided.");
			} else {
				Object salt = null;
				if (clientDetails instanceof SaltedClientSecret) {
					salt = ((SaltedClientSecret) clientDetails).getSalt();
				}

				if (!passwordEncoder.isPasswordValid(clientDetails.getClientSecret(), assertedSecret, salt)) {
					throw new UnauthorizedClientException("Invalid client secret.");
				}
			}
		}

		if (clientDetails.isScoped()) {
			if (authorizationScope.isEmpty()) {
				throw new InvalidScopeException("Invalid scope (none)");
			}
			List<String> validScope = clientDetails.getScope();
			for (String scope : authorizationScope) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope);
				}
			}
		}

		List<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidGrantException("Unauthorized grant type: " + grantType);
		}

		ClientToken clientAuth = new ClientToken(clientId, new HashSet<String>(clientDetails.getResourceIds()),
				clientSecret, authorizationScope, clientDetails.getAuthorities());
		Authentication userAuth = storedAuth.getUserAuthentication();
		return tokenServices.createAccessToken(new OAuth2Authentication(clientAuth, userAuth));

	}

}
