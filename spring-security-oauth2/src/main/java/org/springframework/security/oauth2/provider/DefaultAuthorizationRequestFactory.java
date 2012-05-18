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

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;

/**
 * Default implementation of {@link AuthorizationRequestFactory} which validates grant types and scopes and fills in
 * scopes with the default values from the client if they are missing.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultAuthorizationRequestFactory implements AuthorizationRequestFactory {

	private final ClientDetailsService clientDetailsService;

	public DefaultAuthorizationRequestFactory(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters, String clientId, String grantType, Set<String> scopes) {

		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, clientDetails);
		if (scopes != null) {
			validateScope(clientDetails, scopes);
		}
		if (scopes == null || scopes.isEmpty()) {
			// If no scopes are specified in the incoming data, use the default values registered with the client
			// (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
			// least obnoxious choice as a default).
			scopes = clientDetails.getScope();
		}
		return new AuthorizationRequest(clientId, scopes, clientDetails.getAuthorities(),
				clientDetails.getResourceIds());

	}

	private void validateScope(ClientDetails clientDetails, Set<String> scopes) {

		if (clientDetails.isScoped()) {
			Set<String> validScope = clientDetails.getScope();
			for (String scope : scopes) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, validScope);
				}
			}
		}

	}

	private void validateGrantType(String grantType, ClientDetails clientDetails) {
		Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidGrantException("Unauthorized grant type: " + grantType);
		}
	}

}
