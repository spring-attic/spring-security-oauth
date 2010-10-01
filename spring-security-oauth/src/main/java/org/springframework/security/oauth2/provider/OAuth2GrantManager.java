package org.springframework.security.oauth2.provider;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * The manager of OAuth2 authorization grants.
 *
 * @author Ryan Heaton
 */
public interface OAuth2GrantManager {

  /**
   * Set up an authentication request for the specific grant type.
   *
   * @param grantType The grant type.
   * @param request The HTTP request.
   * @return The authentication, or null if the grant type is unsupported.
   */
  Authentication setupAuthentication(String grantType, HttpServletRequest request);

}
