package org.springframework.security.oauth2.client.token;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * A manager for an , which knows how to obtain an access token for a specific resources.
 *
 * @author Ryan Heaton
 */
public interface AccessTokenProvider {

  /**
   * Obtain a new access token for the specified protected resource.
   *
   * @param details The protected resource for which this provider is to obtain an access token.
   * @param parameters The parameters of the request giving context for the token details if any.
   * @return The access token for the specified protected resource. The return value may NOT be null.
   * @throws UserRedirectRequiredException If the provider requires the current user to be redirected for authorization.
   * @throws AccessDeniedException If the user denies access to the protected resource.
   */
  public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException;

  /**
   * Whether this provider supports the specified resource.
   *
   * @param resource The resource.
   * @return Whether this provider supports the specified resource.
   */
  public boolean supportsResource(OAuth2ProtectedResourceDetails resource);
}
