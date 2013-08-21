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

import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Default implementation of {@link OAuth2RequestFactory} which initializes fields from the parameters map,
 * validates grant types and scopes, and fills in scopes with the default values from the client if they are missing.
 * 
 * @author Dave Syer
 * @author Amanda Anganes
 * 
 */
public class DefaultOAuth2RequestFactory implements OAuth2RequestFactory {

	private final ClientDetailsService clientDetailsService;
	
	public DefaultOAuth2RequestFactory(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {
		
		String clientId = authorizationParameters.get(OAuth2Utils.CLIENT_ID);
		Set<String> scopes = OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.SCOPE));
		String state = authorizationParameters.get(OAuth2Utils.STATE);
		String redirectUri = authorizationParameters.get(OAuth2Utils.REDIRECT_URI);
		Set<String> responseTypes = OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE));
				
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

		if ((scopes == null || scopes.isEmpty())) {
			// If no scopes are specified in the incoming data, use the default values registered with the client
			// (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
			// least obnoxious choice as a default).
			scopes = clientDetails.getScope();
		}

		AuthorizationRequest request = new AuthorizationRequest(authorizationParameters, Collections.<String, String> emptyMap(), 
				clientId, scopes, null, null, false, state, redirectUri, responseTypes);
		
		request.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);
		
		return request;

	}

	public OAuth2Request createOAuth2Request(AuthorizationRequest request) {
		return request.createOAuth2Request();
	}
	
	public TokenRequest createTokenRequest(Map<String, String> requestParameters) {

		String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
		Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));
		String grantType = requestParameters.get(OAuth2Utils.GRANT_TYPE);
		
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

		if ((scopes == null || scopes.isEmpty())) {
			// If no scopes are specified in the incoming data, use the default values registered with the client
			// (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
			// least obnoxious choice as a default).
			scopes = clientDetails.getScope();
		}

		TokenRequest tokenRequest = new TokenRequest(requestParameters, clientId, scopes, grantType);
		
		return tokenRequest;
	}

	public TokenRequest createTokenRequest(AuthorizationRequest authorizationRequest, String grantType) {
		TokenRequest tokenRequest = new TokenRequest(authorizationRequest.getRequestParameters(), authorizationRequest.getClientId(), authorizationRequest.getScope(), grantType);
		return tokenRequest;
	}

	public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest) {
		return tokenRequest.createOAuth2Request(client);
	}

}
