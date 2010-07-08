package org.springframework.security.oauth.provider;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;

import javax.servlet.http.HttpServletRequest;

/**
 * Callback interface for handing authentication details that are used when an authenticated request for a protected resource is received.
 *
 * @author Ryan Heaton
 */
public interface OAuthAuthenticationHandler {

  /**
   * Create the authentication object for an authenticated OAuth request.
   *
   * @param request The request that was successfully authenticated.
   * @param authentication The consumer authentication (details about how the request was authenticated).
   * @param authToken The OAuth token associated with the authentication. This token MAY be null if no authenticated token was needed to successfully
   * authenticate the request (for example, in the case of 2-legged OAuth).
   * @return The new authentication object. For example, the user authentication if the request is made on behalf of a user.
   */
  Authentication createAuthentication(HttpServletRequest request, ConsumerAuthentication authentication, OAuthAccessProviderToken authToken);
}
