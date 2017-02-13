/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
public class JwkTokenStore implements TokenStore {
	private final JwtTokenStore delegate;

	public JwkTokenStore(String jwkSetUrl) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		JwkDefinitionSource jwkDefinitionSource = new JwkDefinitionSource(jwkSetUrl);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		this.delegate = new JwtTokenStore(accessTokenConverter);
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return this.delegate.readAuthentication(token);
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return this.delegate.readAuthentication(token);
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		throw this.operationNotSupported();
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.delegate.readAccessToken(tokenValue);
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken token) {
		throw this.operationNotSupported();
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		throw this.operationNotSupported();
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		throw this.operationNotSupported();
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		throw this.operationNotSupported();
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken token) {
		throw this.operationNotSupported();
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		throw this.operationNotSupported();
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		throw this.operationNotSupported();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		throw this.operationNotSupported();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		throw this.operationNotSupported();
	}

	private JwkException operationNotSupported() {
		return new JwkException("This operation is currently not supported.");
	}
}