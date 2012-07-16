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

package org.springframework.security.oauth2.provider.client;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * @author Dave Syer
 * 
 */
public class ClientCredentialsTokenGranter extends AbstractTokenGranter {

	private static final String GRANT_TYPE = "client_credentials";

	public ClientCredentialsTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService) {
		super(tokenServices, clientDetailsService, GRANT_TYPE);
	}

	@Override
	public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
		OAuth2AccessToken token = super.grant(grantType, authorizationRequest);
		if (token != null) {
			DefaultOAuth2AccessToken norefresh = new DefaultOAuth2AccessToken(token);
			// The spec says that client credentials are not allowed to get a refresh token
			norefresh.setRefreshToken(null);
			token = norefresh;
		}
		return token;
	}

}
