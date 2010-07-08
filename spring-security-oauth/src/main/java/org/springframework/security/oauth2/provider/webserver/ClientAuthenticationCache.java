package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic interface for caching a client authentication token.
 *
 * @author Ryan Heaton
 */
public interface ClientAuthenticationCache {

  /**
   * Store the specified authentication in the cache.
   *
   * @param auth The authentication.
   * @param request The request.
   * @param response The response.
   */
  void saveAuthentication(ClientAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response);

  /**
   * Update specified authentication in the cache.
   *
   * @param auth The authentication.
   * @param request The request.
   * @param response The response.
   */
  void updateAuthentication(ClientAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response);

  /**
   * Read the authentication from the cache.
   *
   * @param request The request.
   * @param response The response.
   * @return The authentication, or null if none.
   */
  ClientAuthenticationToken getAuthentication(HttpServletRequest request, HttpServletResponse response);

  /**
   * Remove the authentication from the cache.
   *
   * @param request The request.
   * @param response The response.
   */
  void removeAuthentication(HttpServletRequest request, HttpServletResponse response);
}
