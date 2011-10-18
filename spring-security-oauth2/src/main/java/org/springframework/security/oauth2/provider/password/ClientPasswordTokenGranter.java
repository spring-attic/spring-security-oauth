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

package org.springframework.security.oauth2.provider.password;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.SaltedClientSecret;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.OAuth2ProviderTokenServices;

/**
 * @author Dave Syer
 * 
 */
public class ClientPasswordTokenGranter implements TokenGranter {

	private static final String GRANT_TYPE = "password";
	private final OAuth2ProviderTokenServices tokenServices;
	private final ClientDetailsService clientDetailsService;
	private final AuthenticationManager authenticationManager;
	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

	public ClientPasswordTokenGranter(AuthenticationManager authenticationManager, OAuth2ProviderTokenServices tokenServices, ClientDetailsService clientDetailsService) {
		this.authenticationManager = authenticationManager;
		this.tokenServices = tokenServices;
		this.clientDetailsService = clientDetailsService;
	}

	public OAuth2AccessToken grant(String grantType, Map<String, String> parameters, String clientId,
			String clientSecret, Set<String> authorizationScope) {

		if (!GRANT_TYPE.equals(grantType)) {
			return null;
		}
		
		String username = parameters.get("username");
		String password = parameters.get("password");

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
		
		ClientToken clientAuth = new ClientToken(clientId, new HashSet<String>(
				clientDetails.getResourceIds()), clientSecret, authorizationScope, clientDetails.getAuthorities());

		Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
		userAuth = authenticationManager.authenticate(userAuth);
		if (userAuth==null || !userAuth.isAuthenticated()) {
			throw new InsufficientAuthenticationException("There is no currently logged in user");
		}

		return tokenServices.createAccessToken(new OAuth2Authentication(clientAuth, userAuth));

	}

}
