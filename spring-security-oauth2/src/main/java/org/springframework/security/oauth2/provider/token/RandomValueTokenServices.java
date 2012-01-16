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

import java.util.Date;
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
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Base implementation for token services that uses random values to generate tokens.
 * <p>
 * Persistence is delegated to a {@code TokenStore} implementation.
 * 
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 */
public class RandomValueTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
		InitializingBean {

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private boolean supportRefreshToken = false;

	private boolean reuseRefreshToken = true;

	private TokenStore tokenStore;

	/**
	 * Initialize these token services. If no random generator is set, one will be created.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenStore must be set");
	}

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

		OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
		if (existingAccessToken!=null) {
			if (existingAccessToken.isExpired()) {
				tokenStore.removeAccessToken(existingAccessToken.getValue());
			} else {
				return existingAccessToken;
			}
		}

		ExpiringOAuth2RefreshToken refreshToken = null;
		if (supportRefreshToken) {
			refreshToken = createRefreshToken(authentication);
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		return accessToken;
	}

	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, Set<String> scope)
			throws AuthenticationException {

		if (!supportRefreshToken) {
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

		if (!reuseRefreshToken) {
			tokenStore.removeRefreshToken(refreshTokenValue);
			refreshToken = createRefreshToken(authentication);
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		return accessToken;
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
			AuthorizationRequest clientAuth = authentication.getAuthorizationRequest();
			Set<String> originalScope = clientAuth.getScope();
			if (originalScope == null || !originalScope.containsAll(scope)) {
				throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope
						+ ".");
			}
			else {
				narrowed = new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
			}
		}
		return narrowed;
	}

	protected boolean isExpired(ExpiringOAuth2RefreshToken refreshToken) {
		return refreshToken.getExpiration() == null
				|| System.currentTimeMillis() > refreshToken.getExpiration().getTime();
	}

	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (accessToken.isExpired()) {
			tokenStore.removeAccessToken(accessTokenValue);
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}

		return tokenStore.readAuthentication(accessToken);
	}

	protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		ExpiringOAuth2RefreshToken refreshToken;
		String refreshTokenValue = UUID.randomUUID().toString();
		refreshToken = new ExpiringOAuth2RefreshToken(refreshTokenValue, new Date(System.currentTimeMillis()
				+ (refreshTokenValiditySeconds * 1000L)));
		tokenStore.storeRefreshToken(refreshToken, authentication);
		return refreshToken;
	}

	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		String tokenValue = UUID.randomUUID().toString();
		OAuth2AccessToken token = new OAuth2AccessToken(tokenValue);
		token.setExpiration(new Date(System.currentTimeMillis() + (accessTokenValiditySeconds * 1000L)));
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getAuthorizationRequest().getScope());
		return token;
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
	 * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
	 */
	public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
		this.accessTokenValiditySeconds = accessTokenValiditySeconds;
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
