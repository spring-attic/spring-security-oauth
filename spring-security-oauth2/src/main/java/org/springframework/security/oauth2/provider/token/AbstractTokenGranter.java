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
package org.springframework.security.oauth2.provider.token;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;

/**
 * @author Dave Syer
 * 
 */
public abstract class AbstractTokenGranter implements TokenGranter {
	
	protected final Log logger = LogFactory.getLog(getClass());

	private final AuthorizationServerTokenServices tokenServices;

	private final ClientDetailsService clientDetailsService;
	
	private final String grantType;

	protected AbstractTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService, String grantType) {
		this.clientDetailsService = clientDetailsService;
		this.grantType = grantType;
		this.tokenServices = tokenServices;
	}

	public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {

		if (!this.grantType.equals(grantType)) {
			return null;
		}
		
		String clientId = authorizationRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);
		
		logger.debug("Getting access token for: " + clientId);
		return getAccessToken(authorizationRequest);

	}

	protected OAuth2AccessToken getAccessToken(AuthorizationRequest authorizationRequest) {
		DefaultAuthorizationRequest outgoingRequest  = new DefaultAuthorizationRequest(authorizationRequest);
		outgoingRequest.setApproved(true);
		// FIXME: do we need to explicitly set approved flag here?
		return tokenServices.createAccessToken(getOAuth2Authentication(outgoingRequest));
	}

	protected OAuth2Authentication getOAuth2Authentication(AuthorizationRequest authorizationRequest) {
		return new OAuth2Authentication(authorizationRequest, null);
	}

	protected void validateGrantType(String grantType, ClientDetails clientDetails) {
		Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidGrantException("Unauthorized grant type: " + grantType);
		}
	}

	protected AuthorizationServerTokenServices getTokenServices() {
		return tokenServices;
	}

}
