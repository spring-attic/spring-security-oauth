package org.springframework.security.oauth2.client.filter.flash;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Services for "remembering" the access tokens that have been obtained for the duration of a single client interaction
 * (which may be multiple HTTP requests).
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface ClientTokenFlashServices {

	/**
	 * Load any remembered tokens for the given request.
	 * 
	 * @param request The request.
	 * @param response The response.
	 * @return The tokens (mapped by resource id), or null if none are remembered.
	 */
	Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Remember the specified tokens for the given request.
	 * 
	 * @param tokens The tokens (null to forget all tokens).
	 * @param request The request.
	 * @param response The response.
	 */
	void rememberTokens(Map<String, OAuth2AccessToken> tokens, HttpServletRequest request, HttpServletResponse response);
}
