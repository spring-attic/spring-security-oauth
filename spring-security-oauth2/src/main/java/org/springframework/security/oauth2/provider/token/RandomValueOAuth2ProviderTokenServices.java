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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenDetails;
import org.springframework.security.oauth2.provider.refresh.RefreshedAuthenticationToken;

import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

/**
 * Base implementation for token services that uses random values to generate tokens. Only the persistence mechanism
 * is left unimplemented.<br/><br/>
 *
 * @author Ryan Heaton
 */
public abstract class RandomValueOAuth2ProviderTokenServices implements OAuth2ProviderTokenServices, InitializingBean {

	private Random random;
	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; //default 30 days.
	private int accessTokenValiditySeconds = 60 * 60 * 12; //default 12 hours.
	private boolean supportRefreshToken = false;
	private boolean reuseRefreshToken = true;
	private int tokenSecretLengthBytes = 80;

	/**
	 * Initialze these token services. If no random generator is set, one will be created.
	 *
	 * @throws Exception
	 */
	public void afterPropertiesSet() throws Exception {
		if (random == null) {
			random = new SecureRandom();
		}
	}

	/**
	 * Read the authentication stored under the specified token value.
	 *
	 * @param token The token value under which the authentication is stored.
	 * @return The authentication, or null if none.
	 */
	protected abstract OAuth2Authentication readAuthentication(OAuth2AccessToken token);

	/**
	 * Store an access token.
	 *
	 * @param token		  The token to store.
	 * @param authentication The authentication associated with the token.
	 */
	protected abstract void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication);

	/**
	 * Read an access token from the store.
	 *
	 * @param tokenValue The token value.
	 * @return The access token to read.
	 */
	protected abstract OAuth2AccessToken readAccessToken(String tokenValue);

	/**
	 * Remove an access token from the database.
	 *
	 * @param tokenValue The token to remove from the database.
	 */
	protected abstract void removeAccessToken(String tokenValue);

	/**
	 * Read the authentication stored under the specified token value.
	 *
	 * @param token The token value under which the authentication is stored.
	 * @return The authentication, or null if none.
	 */
	protected abstract OAuth2Authentication readAuthentication(ExpiringOAuth2RefreshToken token);

	/**
	 * Store the specified refresh token in the database.
	 *
	 * @param refreshToken   The refresh token to store.
	 * @param authentication The authentication associated with the refresh token.
	 */
	protected abstract void storeRefreshToken(ExpiringOAuth2RefreshToken refreshToken, OAuth2Authentication authentication);

	/**
	 * Read a refresh token from the store.
	 *
	 * @param tokenValue The value of the token to read.
	 * @return The token.
	 */
	protected abstract ExpiringOAuth2RefreshToken readRefreshToken(String tokenValue);

	/**
	 * Remove a refresh token from the database.
	 *
	 * @param tokenValue The value of the token to remove from the database.
	 */
	protected abstract void removeRefreshToken(String tokenValue);

	/**
	 * Remove an access token using a refresh token. This functionality is necessary so refresh tokens can't be used to create an unlimited number of
	 * access tokens.
	 *
	 * @param refreshToken The refresh token.
	 */
	protected abstract void removeAccessTokenUsingRefreshToken(String refreshToken);

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		ExpiringOAuth2RefreshToken refreshToken = null;
		if (isSupportRefreshToken()) {
			refreshToken = createRefreshToken(authentication);
		}

		return createAccessToken(authentication, refreshToken);
	}

	public OAuth2AccessToken refreshAccessToken(RefreshTokenDetails tokenDetails) throws AuthenticationException {
		String refreshTokenValue = tokenDetails.getRefreshToken();
		if (!isSupportRefreshToken()) {
			throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
		}

		removeAccessTokenUsingRefreshToken(refreshTokenValue); //clear out any access tokens already associated with the refresh token.

		ExpiringOAuth2RefreshToken refreshToken = readRefreshToken(refreshTokenValue);
		if (refreshToken == null) {
			throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
		}
		else if (isExpired(refreshToken)) {
			removeRefreshToken(refreshTokenValue);
			throw new InvalidTokenException("Invalid refresh token: " + refreshToken);
		}

		OAuth2Authentication authentication = createRefreshedAuthentication(readAuthentication(refreshToken), tokenDetails.getScope());

		if (!isReuseRefreshToken()) {
			removeRefreshToken(refreshTokenValue);
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
			ClientAuthenticationToken clientAuth = authentication.getClientAuthentication();
			Set<String> originalScope = clientAuth.getScope();
			if (originalScope == null || !originalScope.containsAll(scope)) {
				throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope + ".");
			}
			else {
				narrowed = new OAuth2Authentication(new RefreshedAuthenticationToken(clientAuth.getClientId(), clientAuth.getResourceIds(), clientAuth.getClientSecret(), clientAuth.getScope(), clientAuth.getAuthorities()), authentication.getUserAuthentication());
			}
		}
		return narrowed;
	}

	protected boolean isExpired(ExpiringOAuth2RefreshToken refreshToken) {
		return refreshToken.getExpiration() == null || System.currentTimeMillis() > refreshToken.getExpiration().getTime();
	}

	private boolean isExpired(OAuth2AccessToken accessToken) {
		return accessToken.getExpiration() == null || System.currentTimeMillis() > accessToken.getExpiration().getTime();
	}

	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
		OAuth2AccessToken accessToken = readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (isExpired(accessToken)) {
			removeAccessToken(accessTokenValue);
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}

		return readAuthentication(accessToken);
	}

	protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		ExpiringOAuth2RefreshToken refreshToken;
		refreshToken = new ExpiringOAuth2RefreshToken();
		String refreshTokenValue = UUID.randomUUID().toString();
		refreshToken.setValue(refreshTokenValue);
		refreshToken.setExpiration(new Date(System.currentTimeMillis() + (getRefreshTokenValiditySeconds() * 1000L)));
		storeRefreshToken(refreshToken, authentication);
		return refreshToken;
	}

	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		OAuth2AccessToken token = new OAuth2AccessToken();
		String tokenValue = UUID.randomUUID().toString();
		token.setValue(tokenValue);
		token.setExpiration(new Date(System.currentTimeMillis() + (getAccessTokenValiditySeconds() * 1000L)));
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getClientAuthentication().getScope());
		storeAccessToken(token, authentication);
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
}