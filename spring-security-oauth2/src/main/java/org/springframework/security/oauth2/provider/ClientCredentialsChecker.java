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
package org.springframework.security.oauth2.provider;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;

/**
 * @author Dave Syer
 * 
 */
public class ClientCredentialsChecker {

	private final ClientDetailsService clientDetailsService;

	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

	public ClientCredentialsChecker(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	public ClientToken validateCredentials(String grantType, String clientId, String clientSecret) {
		return this.validateCredentials(grantType, clientId, clientSecret, null);
	}
	
	public ClientToken validateCredentials(String grantType, String clientId, String clientSecret, Set<String> scopes) {

		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, clientDetails);
		if (scopes != null) {
			validateScope(clientDetails, scopes);
		}
		validateClient(clientDetails, clientSecret);

		return new ClientToken(clientId, new HashSet<String>(clientDetails.getResourceIds()), clientSecret, scopes,
				clientDetails.getAuthorities());

	}

	private void validateClient(ClientDetails clientDetails, String clientSecret) {
		if (clientDetails.isSecretRequired()) {
			String assertedSecret = clientSecret;
			if (assertedSecret == null) {
				throw new UnauthorizedClientException("Client secret is required but not provided.");
			}
			else {
				Object salt = null;
				if (clientDetails instanceof SaltedClientSecret) {
					salt = ((SaltedClientSecret) clientDetails).getSalt();
				}

				if (!passwordEncoder.isPasswordValid(clientDetails.getClientSecret(), assertedSecret, salt)) {
					throw new UnauthorizedClientException("Invalid client secret.");
				}
			}
		}
	}

	private void validateScope(ClientDetails clientDetails, Set<String> scopes) {

		if (clientDetails.isScoped()) {
			if (scopes.isEmpty()) {
				throw new InvalidScopeException("Invalid scope (none)");
			}
			List<String> validScope = clientDetails.getScope();
			for (String scope : scopes) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope);
				}
			}
		}

	}

	private void validateGrantType(String grantType, ClientDetails clientDetails) {
		List<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidGrantException("Unauthorized grant type: " + grantType);
		}
	}

}
