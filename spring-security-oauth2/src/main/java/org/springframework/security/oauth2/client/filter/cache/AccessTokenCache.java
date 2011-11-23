package org.springframework.security.oauth2.client.filter.cache;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Services for remembering the access tokens that have been obtained for the duration of a single client interaction
 * (which may be multiple HTTP requests).
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface AccessTokenCache {

	/**
	 * Load any remembered tokens for the given request.
	 * 
	 * @param request The request.
	 * @param response The response.
	 * @return The tokens (mapped by resource id), or empty if none are remembered.  Never null.
	 */
	Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Remember the specified tokens for the given request.
	 * 
	 * @param map The tokens (null or empty to forget all tokens).
	 * @param request The request.
	 * @param response The response.
	 */
	void rememberTokens(Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> map, HttpServletRequest request, HttpServletResponse response);
}
