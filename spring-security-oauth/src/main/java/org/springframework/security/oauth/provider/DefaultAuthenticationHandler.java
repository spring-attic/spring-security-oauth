package org.springframework.security.oauth.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;

import javax.servlet.http.HttpServletRequest;

/**
 * The default authentication handler.
 *
 * @author Ryan Heaton
 */
public class DefaultAuthenticationHandler implements OAuthAuthenticationHandler {

  /**
   * Default implementation returns the user authentication associated with the auth token, if the token is provided. Otherwise, the consumer authentication
   * is returned.
   *
   * @param request The request that was successfully authenticated.
   * @param authentication The consumer authentication (details about how the request was authenticated).
   * @param authToken The OAuth token associated with the authentication. This token MAY be null if no authenticated token was needed to successfully
   * authenticate the request (for example, in the case of 2-legged OAuth).
   * @return The authentication.
   */
  public Authentication createAuthentication(HttpServletRequest request, ConsumerAuthentication authentication, OAuthAccessProviderToken authToken) {
    if (authToken != null) {
      Authentication userAuthentication = authToken.getUserAuthentication();
      if (userAuthentication instanceof AbstractAuthenticationToken) {
        //initialize the details with the consumer that is actually making the request on behalf of the user.
        ((AbstractAuthenticationToken) userAuthentication).setDetails(new OAuthAuthenticationDetails(request, authentication.getConsumerDetails()));
      }
      return userAuthentication;
    }

    return authentication;
  }
}
