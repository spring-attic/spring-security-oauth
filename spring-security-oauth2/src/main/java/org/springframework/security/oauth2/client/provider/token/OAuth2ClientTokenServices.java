package org.springframework.security.oauth2.client.provider.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * Token services for an OAuth2 access token.
 *
 * @author Ryan Heaton
 */
public interface OAuth2ClientTokenServices {

  /**
   * Get the token for the specified resource for a specified authentication. Implementations are
   * required to ensure that only tokens valid for the specified authentication are returned.
   *
   * @param authentication The current user authentication. Some implementations may not
   * require a user authentication, so this parameter may be null and/or ignored by the implementation.
   * @param resource The resource for which to get the stored access token.
   * @return The token, or null if none was found.
   */
  OAuth2AccessToken getToken(Authentication authentication, OAuth2ProtectedResourceDetails resource);

  /**
   * Store a token for a specified resource for a specified authentication.
   *
   * @param authentication The current user authentication. Some implementations may
   * not require a user authentication, so this parameter may be null and/or ignored by the implementation.
   * @param resource The resource for which to store the token.
   * @param token The token to store.
   */
  void storeToken(Authentication authentication, OAuth2ProtectedResourceDetails resource, OAuth2AccessToken token);

  /**
   * Update a token for a specified resource for a specified authentication.
   *
   * @param authentication The current user authentication. Some implementations may
   * not require a user authentication, so this parameter may be null and/or ignored by the implementation.
   * @param resource The resource for which to update the token.
   * @param oldToken The old token to replace.
   * @param replacement The replacement for the old token.
   */
  void updateToken(Authentication authentication, OAuth2ProtectedResourceDetails resource, OAuth2AccessToken oldToken, OAuth2AccessToken replacement);

  /**
   * Removes the token for the specified resource for a specified authentication.
   *
   * @param authentication The current user authentication. Some implementations may
   * not require a user authentication, so this parameter may be null and/or ignored by the implementation.
   * @param resource The resource for which to remove the token.
   */
  void removeToken(Authentication authentication, OAuth2ProtectedResourceDetails resource);

}
