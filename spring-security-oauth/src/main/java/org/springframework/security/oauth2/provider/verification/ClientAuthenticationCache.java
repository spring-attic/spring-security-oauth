package org.springframework.security.oauth2.provider.verification;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic interface for caching a client authentication token. An authentication cache is needed for verification services
 * because the authentication needs to be persistent across multiple requests.
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
  void saveAuthentication(VerificationCodeAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response);

  /**
   * Update specified authentication in the cache.
   *
   * @param auth The authentication.
   * @param request The request.
   * @param response The response.
   */
  void updateAuthentication(VerificationCodeAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response);

  /**
   * Read the authentication from the cache.
   *
   * @param request The request.
   * @param response The response.
   * @return The authentication, or null if none.
   */
  VerificationCodeAuthenticationToken getAuthentication(HttpServletRequest request, HttpServletResponse response);

  /**
   * Remove the authentication from the cache.
   *
   * @param request The request.
   * @param response The response.
   */
  void removeAuthentication(HttpServletRequest request, HttpServletResponse response);
}
