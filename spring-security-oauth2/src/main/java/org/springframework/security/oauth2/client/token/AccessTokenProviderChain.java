package org.springframework.security.oauth2.client.token;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

/**
 * A chain of OAuth2 access token providers. This implementation will iterate through its chain to find the first
 * provider that supports the resource and use it to obtain the access token. Note that the order of the chain is
 * relevant.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AccessTokenProviderChain extends OAuth2AccessTokenSupport implements AccessTokenProvider, InitializingBean {

	private final List<AccessTokenProvider> chain;

	public AccessTokenProviderChain(List<AccessTokenProvider> chain) {
		this.chain = chain == null ? Collections.<AccessTokenProvider> emptyList() : Collections
				.unmodifiableList(chain);
	}

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(resource)) {
				return true;
			}
		}
		return false;
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				return true;
			}
		}
		return false;
	}

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		OAuth2AccessToken accessToken = null;
		OAuth2AccessToken existingToken = null;
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (auth instanceof AnonymousAuthenticationToken) {
			if (!resource.isClientOnly()) {
				throw new InsufficientAuthenticationException(
						"Authentication is required to store an access token (anonymous not allowed)");
			}
		}

		if (resource.isClientOnly() || (auth != null && auth.isAuthenticated())) {
			existingToken = request.getExistingToken();
			if (existingToken != null) {
				if (existingToken.isExpired()) {
					OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
					if (refreshToken != null) {
						accessToken = refreshAccessToken(resource, refreshToken, request);
					}
				}
				else {
					accessToken = existingToken;
				}
			}
		}
		// Give unauthenticated users a chance to get a token and be redirected

		if (accessToken == null) {
			// looks like we need to try to obtain a new token.
			accessToken = obtainNewAccessTokenInternal(resource, request);

			if (accessToken == null) {
				throw new IllegalStateException("An OAuth 2 access token must be obtained or an exception thrown.");
			}
		}

		return accessToken;
	}

	protected OAuth2AccessToken obtainNewAccessTokenInternal(OAuth2ProtectedResourceDetails details,
			AccessTokenRequest request) throws UserRedirectRequiredException, AccessDeniedException {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(details)) {
				return tokenProvider.obtainAccessToken(details, request);
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
	 * @throws UserRedirectRequiredException
	 */
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				return tokenProvider.refreshAccessToken(resource, refreshToken, request);
			}
		}
		throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + resource.getId()
				+ "'. The provider manager is not configured to support it.", resource);
	}

}
