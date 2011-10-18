package org.springframework.security.oauth2.provider.code;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic interface for caching an unconfirmed authorization code token. An authentication cache is needed for
 * authorization services because the authorization code token needs to be persistent across multiple requests.
 * 
 * @author Ryan Heaton
 */
public interface ClientTokenCache {

	/**
	 * Store the specified token in the cache.
	 * 
	 * @param token The token.
	 * @param request The request.
	 * @param response The response.
	 */
	void saveToken(UnconfirmedAuthorizationCodeClientToken token, HttpServletRequest request,
			HttpServletResponse response);

	/**
	 * Update specified token in the cache.
	 * 
	 * @param token The token.
	 * @param request The request.
	 * @param response The response.
	 */
	void updateToken(UnconfirmedAuthorizationCodeClientToken token, HttpServletRequest request,
			HttpServletResponse response);

	/**
	 * Read the token from the cache.
	 * 
	 * @param request The request.
	 * @param response The response.
	 * @return The token, or null if none.
	 */
	UnconfirmedAuthorizationCodeClientToken getToken(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Remove the token from the cache.
	 * 
	 * @param token
	 * @param request The request.
	 * @param response The response.
	 */
	void removeToken(UnconfirmedAuthorizationCodeClientToken token, HttpServletRequest request,
			HttpServletResponse response);
}
