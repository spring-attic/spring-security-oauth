/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.token;

import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Base implementation for token services that uses random values to generate tokens.
 * <p>
 * Persistence is delegated to a {@code TokenStore} implementation.
 * 
 * @author Ryan Heaton
 */
public class RandomValueTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
		InitializingBean {

	private Random random;

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private boolean supportRefreshToken = false;

	private boolean reuseRefreshToken = true;

	private int tokenSecretLengthBytes = 80;

	private TokenStore tokenStore;

	/**
	 * Initialize these token services. If no random generator is set, one will be created.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenStore must be set");
		if (random == null) {
			random = new SecureRandom();
		}
	}

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		ExpiringOAuth2RefreshToken refreshToken = null;
		if (isSupportRefreshToken()) {
			refreshToken = createRefreshToken(authentication);
		}

		return createAccessToken(authentication, refreshToken);
	}

	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, Set<String> scope)
			throws AuthenticationException {

		if (!isSupportRefreshToken()) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}

		// clear out any access tokens already associated with the refresh token.
		tokenStore.removeAccessTokenUsingRefreshToken(refreshTokenValue);

		ExpiringOAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
		if (refreshToken == null) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}
		else if (isExpired(refreshToken)) {
			tokenStore.removeRefreshToken(refreshTokenValue);
			throw new InvalidGrantException("Invalid refresh token: " + refreshToken);
		}

		OAuth2Authentication authentication = createRefreshedAuthentication(
				tokenStore.readAuthentication(refreshToken), scope);

		if (!isReuseRefreshToken()) {
			tokenStore.removeRefreshToken(refreshTokenValue);
			refreshToken = createRefreshToken(authentication);
		}

		return createAccessToken(authentication, refreshToken);
	}

	/**
	 * Create a refreshed authentication.
	 * 
	 * @param authentication The authentication.
	 * @param scope The scope for the refreshed token.
	 * @return The refreshed authentication.
	 * @throws InvalidScopeException If the scope requested is invalid or wider than the original scope.
	 */
	private OAuth2Authentication createRefreshedAuthentication(OAuth2Authentication authentication, Set<String> scope) {
		OAuth2Authentication narrowed = authentication;
		if (scope != null && !scope.isEmpty()) {
			ClientToken clientAuth = authentication.getClientAuthentication();
			Set<String> originalScope = clientAuth.getScope();
			if (originalScope == null || !originalScope.containsAll(scope)) {
				throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope
						+ ".");
			}
			else {
				narrowed = new OAuth2Authentication(new ClientToken(clientAuth.getClientId(),
						clientAuth.getResourceIds(), clientAuth.getClientSecret(), clientAuth.getScope(),
						clientAuth.getAuthorities()), authentication.getUserAuthentication());
			}
		}
		return narrowed;
	}

	protected boolean isExpired(ExpiringOAuth2RefreshToken refreshToken) {
		return refreshToken.getExpiration() == null
				|| System.currentTimeMillis() > refreshToken.getExpiration().getTime();
	}

	private boolean isExpired(OAuth2AccessToken accessToken) {
		return accessToken.getExpiration() == null
				|| System.currentTimeMillis() > accessToken.getExpiration().getTime();
	}

	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (isExpired(accessToken)) {
			tokenStore.removeAccessToken(accessTokenValue);
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}

		return tokenStore.readAuthentication(accessToken);
	}

	protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		ExpiringOAuth2RefreshToken refreshToken;
		String refreshTokenValue = UUID.randomUUID().toString();
		refreshToken = new ExpiringOAuth2RefreshToken(refreshTokenValue, new Date(System.currentTimeMillis()
				+ (getRefreshTokenValiditySeconds() * 1000L)));
		tokenStore.storeRefreshToken(refreshToken, authentication);
		return refreshToken;
	}

	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		String tokenValue = UUID.randomUUID().toString();
		OAuth2AccessToken token = new OAuth2AccessToken(tokenValue);
		token.setExpiration(new Date(System.currentTimeMillis() + (getAccessTokenValiditySeconds() * 1000L)));
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getClientAuthentication().getScope());
		tokenStore.storeAccessToken(token, authentication);
		return token;
	}

	/**
	 * The length of the token secret in bytes, before being base64-encoded.
	 * 
	 * @return The length of the token secret in bytes.
	 */
	public int getTokenSecretLengthBytes() {
		return tokenSecretLengthBytes;
	}

	/**
	 * The length of the token secret in bytes, before being base64-encoded.
	 * 
	 * @param tokenSecretLengthBytes The length of the token secret in bytes, before being base64-encoded.
	 */
	public void setTokenSecretLengthBytes(int tokenSecretLengthBytes) {
		this.tokenSecretLengthBytes = tokenSecretLengthBytes;
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @return The random value generator used to create token secrets.
	 */
	public Random getRandom() {
		return random;
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @param random The random value generator used to create token secrets.
	 */
	public void setRandom(Random random) {
		this.random = random;
	}

	/**
	 * The validity (in seconds) of the unauthenticated request token.
	 * 
	 * @return The validity (in seconds) of the unauthenticated request token.
	 */
	public int getRefreshTokenValiditySeconds() {
		return refreshTokenValiditySeconds;
	}

	/**
	 * The validity (in seconds) of the unauthenticated request token.
	 * 
	 * @param refreshTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
	 */
	public void setRefreshTokenValiditySeconds(int refreshTokenValiditySeconds) {
		this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
	}

	/**
	 * The validity (in seconds) of the access token.
	 * 
	 * @return The validity (in seconds) of the access token.
	 */
	public int getAccessTokenValiditySeconds() {
		return accessTokenValiditySeconds;
	}

	/**
	 * The validity (in seconds) of the access token.
	 * 
	 * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
	 */
	public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
		this.accessTokenValiditySeconds = accessTokenValiditySeconds;
	}

	/**
	 * Whether to support the refresh token.
	 * 
	 * @return Whether to support the refresh token.
	 */
	public boolean isSupportRefreshToken() {
		return supportRefreshToken;
	}

	/**
	 * Whether to support the refresh token.
	 * 
	 * @param supportRefreshToken Whether to support the refresh token.
	 */
	public void setSupportRefreshToken(boolean supportRefreshToken) {
		this.supportRefreshToken = supportRefreshToken;
	}

	/**
	 * Whether to reuse refresh tokens (until expired).
	 * 
	 * @return Whether to reuse refresh tokens (until expired).
	 */
	public boolean isReuseRefreshToken() {
		return reuseRefreshToken;
	}

	/**
	 * Whether to reuse refresh tokens (until expired).
	 * 
	 * @param reuseRefreshToken Whether to reuse refresh tokens (until expired).
	 */
	public void setReuseRefreshToken(boolean reuseRefreshToken) {
		this.reuseRefreshToken = reuseRefreshToken;
	}

	/**
	 * Sets the persistence strategy for token storage.
	 * 
	 * @param tokenStore the store for access and refresh tokens.
	 */
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}
}
