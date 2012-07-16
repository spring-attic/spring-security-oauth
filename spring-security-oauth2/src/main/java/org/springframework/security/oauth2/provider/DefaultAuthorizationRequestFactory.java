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
import org.springframework.security.oauth2.common.util.OAuth2Utils;

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

	public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters) {

		String clientId = parameters.get("client_id");
		if (clientId == null) {
			throw new InvalidClientException("A client id must be provided");
		}
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		Set<String> scopes = OAuth2Utils.parseParameterList(parameters.get("scope"));
		if ((scopes == null || scopes.isEmpty()) && !isRefreshTokenRequest(parameters)) {
			// If no scopes are specified in the incoming data, use the default values registered with the client
			// (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
			// least obnoxious choice as a default).
			scopes = clientDetails.getScope();
		}
		AuthorizationRequest request = new AuthorizationRequest(parameters, Collections.<String, String> emptyMap(),
				clientId, scopes);
		request = request.addClientDetails(clientDetails);
		return request;

	}

	private boolean isRefreshTokenRequest(Map<String, String> parameters) {
		return "refresh_token".equals(parameters.get("grant_type")) && parameters.get("refresh_token") != null;
	}

}
