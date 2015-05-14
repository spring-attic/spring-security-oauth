/*
 * Copyright 2013-2014 the original author or authors.
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

package demo;

import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * A custom {@link TokenGranter} that always grants a token, and does not authenticate users (hence the client has to be
 * trusted to only send authenticated client details).
 * 
 * @author Dave Syer
 *
 */
public class CustomTokenGranter extends AbstractTokenGranter {

	CustomTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
			OAuth2RequestFactory requestFactory, String grantType) {
		super(tokenServices, clientDetailsService, requestFactory, grantType);
	}

	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		Map<String, String> params = tokenRequest.getRequestParameters();
		String username = params.containsKey("username") ? params.get("username") : "guest";
		List<GrantedAuthority> authorities = params.containsKey("authorities") ? AuthorityUtils
				.createAuthorityList(OAuth2Utils.parseParameterList(params.get("authorities")).toArray(new String[0]))
				: AuthorityUtils.NO_AUTHORITIES;
		Authentication user = new UsernamePasswordAuthenticationToken(username, "N/A", authorities);
		OAuth2Authentication authentication = new OAuth2Authentication(tokenRequest.createOAuth2Request(client), user);
		return authentication;
	}
}