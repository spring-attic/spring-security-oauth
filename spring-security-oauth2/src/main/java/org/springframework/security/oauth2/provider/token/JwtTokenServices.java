/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider.token;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * Token services for authorization server and resource server based on JWT encoded token values. There is no need for
 * shared storage because all of the state is carried in the token values.
 * 
 * @author Dave Syer
 * 
 */
public class JwtTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
		InitializingBean {

	/**
	 * Field name for token id.
	 */
	public static final String TOKEN_ID = "jti";

	private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();

	private ClientDetailsService clientDetailsService;

	private TokenEnhancer accessTokenEnhancer;

	private JwtTokenEnhancer jwtTokenEnhancer = new JwtTokenEnhancer();

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private boolean supportRefreshToken = false;

	private boolean reuseRefreshToken = true;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

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
	 * An access token enhancer that will be applied to a new token before it is saved in the token store.
	 * 
	 * @param accessTokenEnhancer the access token enhancer to set
	 */
	public void setTokenEnhancer(TokenEnhancer accessTokenEnhancer) {
		this.accessTokenEnhancer = accessTokenEnhancer;
	}

	/**
	 * The validity (in seconds) of the refresh token.
	 * 
	 * @param refreshTokenValiditySeconds The validity (in seconds) of the refresh token.
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
	 * The client details service to use for looking up clients (if necessary). Optional if the access token expiry is
	 * set globally via {@link #setAccessTokenValiditySeconds(int)}.
	 * 
	 * @param clientDetailsService the client details service
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	/**
	 * The key generator that is used to extract a unique identifier for an access token.
	 * 
	 * @param authenticationKeyGenerator a key generator
	 */
	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	/**
	 * The key used for verifying signatures produced by this class. This is not used but is returned from the endpoint
	 * to allow resource servers to obtain the key.
	 * 
	 * @param key the signature verification key (typically an RSA public key)
	 */
	public void setVerifierKey(String key) {
		jwtTokenEnhancer.setVerifierKey(key);
	}

	/**
	 * Sets the JWT signing key. It can be either a simple MAC key or an RSA key. RSA keys should be in OpenSSH format,
	 * as produced by <tt>ssh-keygen</tt>.
	 * 
	 * @param key the key to be used for signing JWTs.
	 */
	public void setSigningKey(String key) {
		jwtTokenEnhancer.setSigningKey(key);
	}

	public void afterPropertiesSet() throws Exception {
		jwtTokenEnhancer.afterPropertiesSet();
	}

	public OAuth2Authentication loadAuthentication(String token) throws AuthenticationException {
		return tokenConverter.extractAuthentication(decode(token));
	}

	public OAuth2AccessToken readAccessToken(String token) {
		return tokenConverter.extractAccessToken(token, decode(token));
	}

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(getAccessToken(authentication));
		result.setRefreshToken(createRefreshToken(authentication));
		return result;
	}
	
	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest request)
			throws AuthenticationException {

		if (!supportRefreshToken) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}

		OAuth2Authentication authentication = loadAuthentication(refreshTokenValue);
		String clientId = authentication.getOAuth2Request().getClientId();
		if (clientId == null || !clientId.equals(request.getClientId())) {
			throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
		}

		OAuth2AccessToken refreshTokenData = readAccessToken(refreshTokenValue);
		if (isExpired(refreshTokenData)) {
			throw new InvalidTokenException("Invalid refresh token (expired): " + refreshTokenValue);
		}

		authentication = createRefreshedAuthentication(authentication, request.getScope());

		OAuth2AccessToken accessToken = createAccessToken(authentication);
		if (!reuseRefreshToken) {
			OAuth2RefreshToken refreshToken = createRefreshToken(authentication);
			DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
			result.setRefreshToken(refreshToken);
		}

		return accessToken;
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {

		String tokenId = authenticationKeyGenerator.extractKey(authentication);
		DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(tokenId);

		Map<String, Object> info = new LinkedHashMap<String, Object>();
		info.put(TOKEN_ID, tokenId);
		result.setAdditionalInformation(info);

		int validitySeconds = getAccessTokenValiditySeconds(authentication.getOAuth2Request());
		if (validitySeconds > 0) {
			result.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}

		result.setScope(authentication.getOAuth2Request().getScope());

		if (accessTokenEnhancer != null) {
			result = new DefaultOAuth2AccessToken(accessTokenEnhancer.enhance(result, authentication));
		}

		DefaultOAuth2AccessToken token = result.setValue(encode(result, authentication));

		return token;

	}

	/**
	 * Utility method to check if a token is expired.
	 * 
	 * @param expiringToken an access token
	 * @return true if it is expired
	 */
	protected boolean isExpired(OAuth2AccessToken expiringToken) {
		return expiringToken.getExpiration() != null
				&& System.currentTimeMillis() > expiringToken.getExpiration().getTime();
	}

	/**
	 * Is a refresh token supported for this client (or the global setting if
	 * {@link #setClientDetailsService(ClientDetailsService) clientDetailsService} is not set.
	 * @param authorizationRequest the current authorization request
	 * @return boolean to indicate if refresh token is supported
	 */
	protected boolean isSupportRefreshToken(OAuth2Request authorizationRequest) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
			return client.getAuthorizedGrantTypes().contains("refresh_token");
		}
		return this.supportRefreshToken;
	}

	/**
	 * The access token validity period in seconds
	 * @param authorizationRequest the current authorization request
	 * @return the access token validity period in seconds
	 */
	protected int getAccessTokenValiditySeconds(OAuth2Request authorizationRequest) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
			Integer validity = client.getAccessTokenValiditySeconds();
			if (validity != null) {
				return validity;
			}
		}
		return accessTokenValiditySeconds;
	}

	/**
	 * The refresh token validity period in seconds
	 * @param authorizationRequest the current authorization request
	 * @return the refresh token validity period in seconds
	 */
	protected int getRefreshTokenValiditySeconds(OAuth2Request authorizationRequest) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
			Integer validity = client.getRefreshTokenValiditySeconds();
			if (validity != null) {
				return validity;
			}
		}
		return refreshTokenValiditySeconds;
	}

	/**
	 * @param accessToken the access token whose value needs to be encoded
	 * @param authentication the current authentication
	 * @return an access token value encoding the contents of the input token
	 */
	private String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		return jwtTokenEnhancer.encode(accessToken, authentication);
	}

	private Map<String, Object> decode(String token) {
		return jwtTokenEnhancer.decode(token);
	}

	/**
	 * Create a refreshed authentication taking into account the requested scope and the scope of the original
	 * authentication.
	 * 
	 * @param authentication The authentication.
	 * @param scope The scope for the refreshed token.
	 * @return The refreshed authentication.
	 * @throws InvalidScopeException If the scope requested is invalid or wider than the original scope.
	 */
	private OAuth2Authentication createRefreshedAuthentication(OAuth2Authentication authentication, Set<String> scope) {
		OAuth2Authentication narrowed = authentication;
		if (scope != null && !scope.isEmpty()) {
			OAuth2Request clientAuth = authentication.getOAuth2Request();
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

	/**
	 * Create a refresh token (if supported) by encoding an authentication, so it can be recovered when needed without
	 * any need for shared storage.
	 * 
	 * @param authentication the current authentication
	 * @return a refresh token with a JWT encoded value
	 */
	private ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		if (!isSupportRefreshToken(authentication.getOAuth2Request())) {
			return null;
		}
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(getAccessToken(authentication));
		int validitySeconds = getRefreshTokenValiditySeconds(authentication.getOAuth2Request());
		Date expiration = new Date(System.currentTimeMillis() + (validitySeconds * 1000L));
		accessToken.setExpiration(expiration);
		accessToken.setValue(encode(accessToken, authentication));
		ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(accessToken.getValue(),
				expiration);
		return refreshToken;
	}

}
