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

import java.util.Collection;
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
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
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
		ConsumerTokenServices, InitializingBean {

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private boolean supportRefreshToken = false;

	private boolean reuseRefreshToken = true;

	private TokenStore tokenStore;

	private ClientDetailsService clientDetailsService;

	/**
	 * Initialize these token services. If no random generator is set, one will be created.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenStore must be set");
	}

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

		OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
		OAuth2RefreshToken refreshToken = null;
		if (existingAccessToken != null) {
			if (existingAccessToken.isExpired()) {
				if (existingAccessToken.getRefreshToken() != null) {
					refreshToken = existingAccessToken.getRefreshToken();
					// The token store could remove the refresh token, but we want to be sure...
					tokenStore.removeRefreshToken(refreshToken);
				}
				tokenStore.removeAccessToken(existingAccessToken);
			}
			else {
				return existingAccessToken;
			}
		}

		// Only create a new refresh token if there wasn't an existing one associated with an expired access token.
		// Clients might be holding existing refresh tokens, so we re-use it in the case that the old access token
		// expired.
		if (refreshToken == null) {
			refreshToken = createRefreshToken(authentication);
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		if (refreshToken!=null) {
			tokenStore.storeRefreshToken(refreshToken, authentication);
		}
		return accessToken;

	}

	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, Set<String> scope)
			throws AuthenticationException {

		if (!supportRefreshToken) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}

		OAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
		if (refreshToken == null) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}

		// clear out any access tokens already associated with the refresh token.
		tokenStore.removeAccessTokenUsingRefreshToken(refreshToken);

		if (isExpired(refreshToken)) {
			tokenStore.removeRefreshToken(refreshToken);
			throw new InvalidGrantException("Invalid refresh token: " + refreshToken);
		}

		OAuth2Authentication authentication = createRefreshedAuthentication(
				tokenStore.readAuthenticationForRefreshToken(refreshToken), scope);

		if (!reuseRefreshToken) {
			tokenStore.removeRefreshToken(refreshToken);
			refreshToken = createRefreshToken(authentication);
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		return accessToken;
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		return tokenStore.getAccessToken(authentication);
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
						+ ".", originalScope);
			}
			else {
				narrowed = new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
			}
		}
		return narrowed;
	}

	protected boolean isExpired(OAuth2RefreshToken refreshToken) {
		if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiringToken = (ExpiringOAuth2RefreshToken) refreshToken;
			return expiringToken.getExpiration() == null
					|| System.currentTimeMillis() > expiringToken.getExpiration().getTime();
		}
		return false;
	}

	public OAuth2AccessToken readAccessToken(String accessToken) {
		return tokenStore.readAccessToken(accessToken);
	}

	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (accessToken.isExpired()) {
			tokenStore.removeAccessToken(accessToken);
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}

		return tokenStore.readAuthentication(accessToken);
	}

	public String getClientId(String tokenValue) {
		OAuth2Authentication authentication = tokenStore.readAuthentication(tokenValue);
		if (authentication == null) {
			throw new InvalidTokenException("Invalid access token: " + tokenValue);
		}
		AuthorizationRequest authorizationRequest = authentication.getAuthorizationRequest();
		if (authorizationRequest == null) {
			throw new InvalidTokenException("Invalid access token (no client id): " + tokenValue);
		}
		return authorizationRequest.getClientId();
	}

	public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
		return tokenStore.findTokensByUserName(userName);
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		return tokenStore.findTokensByClientId(clientId);
	}

	public boolean revokeToken(String tokenValue) {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
		if (accessToken == null) {
			return false;
		}
		if (accessToken.getRefreshToken() != null) {
			tokenStore.removeRefreshToken(accessToken.getRefreshToken());
		}
		tokenStore.removeAccessToken(accessToken);
		return true;
	}

	protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		if (!supportRefreshToken) {
			return null;
		}
		ExpiringOAuth2RefreshToken refreshToken;
		String refreshTokenValue = UUID.randomUUID().toString();
		refreshToken = createRefreshToken(authentication, refreshTokenValue, new Date(System.currentTimeMillis()
				+ (refreshTokenValiditySeconds * 1000L)));
		tokenStore.storeRefreshToken(refreshToken, authentication);
		return refreshToken;
	}

	protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication,
			String refreshTokenValue, Date expiration) {
		return new ExpiringOAuth2RefreshToken(refreshTokenValue, expiration);
	}

	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		String tokenValue = UUID.randomUUID().toString();
		OAuth2AccessToken token = createAccessToken(authentication, tokenValue);
		int validitySeconds = getAccessTokenValiditySeconds(authentication.getAuthorizationRequest());
		if (validitySeconds > 0) {
			token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getAuthorizationRequest().getScope());
		return token;
	}

	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, String tokenValue) {
		return new OAuth2AccessToken(tokenValue);
	}

	/**
	 * The access token validity period in seconds
	 * @param authorizationRequest the current authorization request
	 * @return the access token validity period in seconds
	 */
	protected int getAccessTokenValiditySeconds(AuthorizationRequest authorizationRequest) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
			if (client.getAccessTokenValiditySeconds() > 0) {
				return client.getAccessTokenValiditySeconds();
			}
		}
		return accessTokenValiditySeconds;
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
	 * The default validity (in seconds) of the access token. Zero or negative for non-expiring tokens. If a client
	 * details service is set the validity period will be read from he client, defaulting to this value if not defined
	 * by the client.
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
	 * The persistence strategy for token storage.
	 * 
	 * @param tokenStore the store for access and refresh tokens.
	 */
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	/**
	 * The client details service to use for looking up clients (if necessary). Optional if the access token expiry is
	 * set globally via {@link #setAccessTokenValiditySeconds(int)}.
	 * 
	 * @param clientDetailsService the client details service
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}
}
