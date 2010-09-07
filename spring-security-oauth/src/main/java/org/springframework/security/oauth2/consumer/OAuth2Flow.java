package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Marker interface for an OAuth2 flow.
 *
 * @author Ryan Heaton
 */
public interface OAuth2Flow {

  /**
   * Obtain a new access token for the specified protected resource.
   *
   * @param details The protected resource for which this flow is to obtain an access token.
   * @return The access token for the specified protected resource.
   * @throws UserRedirectRequiredException If the flow requires the current user to be redirected for authorization.
   * @throws AccessDeniedException If the user denies access to the protected resource.
   */
  public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException;

  /**
   * Whether this flow supports the specified resource.
   *
   * @param resource The resource.
   * @return Whether this flow supports the specified resource.
   */
  public boolean supportsResource(OAuth2ProtectedResourceDetails resource);
}
