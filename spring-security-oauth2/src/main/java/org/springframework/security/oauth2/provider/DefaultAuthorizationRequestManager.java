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

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Default implementation of {@link AuthorizationRequestManager} which validates grant types and scopes and fills in
 * scopes with the default values from the client if they are missing.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultAuthorizationRequestManager implements AuthorizationRequestManager {

	private final ClientDetailsService clientDetailsService;

	private boolean revealValidScopes = false;

	/**
	 * Flag to indicate that when an invalid scope is requested, the valid values should be revealed in the exception
	 * (which is then seen by the client). Default false;
	 * 
	 * @param revealValidScopes the revealValidScopes to set
	 */
	public void setRevealValidScopes(boolean revealValidScopes) {
		this.revealValidScopes = revealValidScopes;
	}

	public DefaultAuthorizationRequestManager(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters) {

		String clientId = parameters.get("client_id");
		if (clientId == null) {
			throw new InvalidClientException("A client id must be provided");
		}
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		Set<String> scopes = OAuth2Utils.parseParameterList(parameters.get("scope"));
		if ((scopes == null || scopes.isEmpty())) {
			// If no scopes are specified in the incoming data, use the default values registered with the client
			// (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
			// least obnoxious choice as a default).
			scopes = clientDetails.getScope();
		}
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(parameters,
				Collections.<String, String> emptyMap(), clientId, scopes);
		request.addClientDetails(clientDetails);
		return request;

	}

	public void validateParameters(Map<String, String> parameters, ClientDetails clientDetails) {
		if (parameters.containsKey("scope")) {
			if (clientDetails.isScoped()) {
				Set<String> validScope = clientDetails.getScope();
				for (String scope : OAuth2Utils.parseParameterList(parameters.get("scope"))) {
					if (!validScope.contains(scope)) {
						InvalidScopeException exception;
						if (revealValidScopes) {
							exception = new InvalidScopeException("Invalid scope: " + scope, validScope);
						}
						else {
							exception = new InvalidScopeException("Invalid scope: " + scope);
						}
						throw exception;
					}
				}
			}
		}
	}

}
