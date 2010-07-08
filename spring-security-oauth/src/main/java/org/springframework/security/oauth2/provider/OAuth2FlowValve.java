package org.springframework.security.oauth2.provider;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * The "valve" for controlling the OAuth 2 flow.
 *
 * @author Ryan Heaton
 */
public interface OAuth2FlowValve {

  /**
   * Set up an authentication request for the specific flow type.
   *
   * @param flowType The flow type.
   * @param request The HTTP request.
   * @return The authentication, or null if the flow type is unsupported.
   */
  Authentication setupAuthentication(String flowType, HttpServletRequest request);

}
