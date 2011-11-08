package org.springframework.security.oauth2.client.token;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.http.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.service.InMemoryOAuth2ClientTokenServices;
import org.springframework.security.oauth2.client.token.service.OAuth2ClientTokenServices;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * A chain of OAuth2 access token providers. This implementation will iterate through its chain to find the first
 * provider that supports the resource and use it to obtain the access token. Note, then, that the order of the chain is
 * relevant.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2AccessTokenProviderChain extends OAuth2AccessTokenSupport implements OAuth2AccessTokenProvider,
		InitializingBean {

	private final List<OAuth2AccessTokenProvider> chain;

	private OAuth2ClientTokenServices tokenServices = new InMemoryOAuth2ClientTokenServices();

	private boolean requireAuthenticated = true;

	public OAuth2AccessTokenProviderChain(List<OAuth2AccessTokenProvider> chain) {
		this.chain = chain == null ? Collections.<OAuth2AccessTokenProvider> emptyList() : Collections
				.unmodifiableList(chain);
	}

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		for (OAuth2AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(resource)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The chain.
	 * 
	 * @return The chain.
	 */
	public List<OAuth2AccessTokenProvider> getChain() {
		return chain;
	}

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.notNull(tokenServices, "OAuth2 token services is required.");
	}

	public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails resource, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {
		OAuth2AccessToken accessToken = null;
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (requireAuthenticated && (auth == null || !auth.isAuthenticated())) {
			throw new OAuth2AccessDeniedException(
					"An authenticated context is required for the current user in order to obtain an access token.",
					resource);
		}
		final OAuth2AccessToken existingToken = tokenServices.getToken(auth, resource);
		if (existingToken != null) {
			if (isExpired(existingToken)) {
				OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
				if (refreshToken != null) {
					accessToken = refreshAccessToken(resource, refreshToken);
				}
			}
			else {
				accessToken = existingToken;
			}
		}

		if (accessToken == null) {
			// looks like we need to try to obtain a new token.
			accessToken = obtainNewAccessTokenInternal(resource, request);

			if (accessToken == null) {
				throw new IllegalStateException("An OAuth 2 access token must be obtained or an exception thrown.");
			}
		}

		// store the token as needed.
		if (!accessToken.equals(existingToken)) {
			if (existingToken == null) {
				tokenServices.storeToken(auth, resource, accessToken);
			}
			else {
				tokenServices.updateToken(auth, resource, existingToken, accessToken);
			}
		}

		return accessToken;
	}

	protected OAuth2AccessToken obtainNewAccessTokenInternal(OAuth2ProtectedResourceDetails details,
			AccessTokenRequest request) throws UserRedirectRequiredException, AccessDeniedException {
		for (OAuth2AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(details)) {
				return tokenProvider.obtainNewAccessToken(details, request);
			}
		}

		throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId()
				+ "'. The provider manager is not configured to support it.", details);
	}

	/**
	 * Obtain a new access token for the specified resource using the refresh token.
	 * 
	 * @param resource The resource.
	 * @param refreshToken The refresh token.
	 * @return The access token, or null if failed.
	 */
	protected OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken) {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "refresh_token");
		form.add("refresh_token", refreshToken.getValue());
		return retrieveToken(form, resource);
	}

	/**
	 * Whether the specified access token is expired.
	 * 
	 * @param token The token.
	 * @return Whether the specified access token is expired.
	 */
	protected boolean isExpired(OAuth2AccessToken token) {
		return token.getExpiration() == null || token.getExpiration().getTime() < System.currentTimeMillis();
	}

	public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public void setRequireAuthenticated(boolean requireAuthenticated) {
		this.requireAuthenticated = requireAuthenticated;
	}

}
