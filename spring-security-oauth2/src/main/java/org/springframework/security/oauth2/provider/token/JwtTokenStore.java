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

package org.springframework.security.oauth2.provider.token;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 *
 */
public class JwtTokenStore implements TokenStore {

	private JwtTokenEnhancer jwtTokenEnhancer;

	/**
	 * Create a JwtTokenStore with this token enhancer (must be shared with the DefaultTokenServices if used).
	 * 
	 * @param jwtTokenEnhancer
	 */
	public JwtTokenStore(JwtTokenEnhancer jwtTokenEnhancer) {
		this.jwtTokenEnhancer = jwtTokenEnhancer;
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return jwtTokenEnhancer.extractAuthentication(jwtTokenEnhancer.decode(token));
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return jwtTokenEnhancer.extractAccessToken(tokenValue, jwtTokenEnhancer.decode(tokenValue));
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken token) {
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		OAuth2AccessToken encodedRefreshToken = readAccessToken(tokenValue);
		ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(encodedRefreshToken.getValue(),
				encodedRefreshToken.getExpiration());
		return refreshToken;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken token) {
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		return null;
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
		return Collections.emptySet();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		return Collections.emptySet();
	}

	public void setTokenEnhancer(JwtTokenEnhancer tokenEnhancer) {
		this.jwtTokenEnhancer = tokenEnhancer;
	}

}
