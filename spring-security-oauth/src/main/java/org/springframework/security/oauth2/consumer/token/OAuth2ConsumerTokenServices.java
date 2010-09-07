package org.springframework.security.oauth2.consumer.token;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.OAuth2ProtectedResourceDetails;

/**
 * Token services for an OAuth2 access token.
 *
 * @author Ryan Heaton
 */
public interface OAuth2ConsumerTokenServices {

  /**
   * Get the token for the specified protected resource.
   *
   * @param resource The resource for which to get the stored access token.
   * @return The token, or null if none was found.
   */
  OAuth2AccessToken getToken(OAuth2ProtectedResourceDetails resource);

  /**
   * Store a token for a specified resource.
   *
   * @param resource The resource for which to store the token.
   * @param token The token to store.
   */
  void storeToken(OAuth2ProtectedResourceDetails resource, OAuth2AccessToken token);

  /**
   * Update a token for a specified resource.
   *
   * @param resource The resource for which to update the token.
   * @param oldToken The old token to replace.
   * @param replacement The replacement for the old token.
   */
  void updateToken(OAuth2ProtectedResourceDetails resource, OAuth2AccessToken oldToken, OAuth2AccessToken replacement);

  /**
   * Removes the token for the specified resource.
   *
   * @param resource The resource for which to remove the token.
   */
  void removeToken(OAuth2ProtectedResourceDetails resource);

}
