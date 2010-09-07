package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Processes a request for an oauth 2 access token.
 *
 * @author Ryan Heaton
 */
public interface OAuth2FlowManager {

  /**
   * Obtain an access token for the specified protected resource.
   *
   * @param resource The protected resource for which this flow is to obtain an access token.
   * @return The access token for the specified protected resource.
   * @throws UserRedirectRequiredException If the flow requires the current user to be redirected for authorization.
   * @throws org.springframework.security.access.AccessDeniedException If the user denies access to the protected resource.
   */
  public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource) throws UserRedirectRequiredException, AccessDeniedException;

}
