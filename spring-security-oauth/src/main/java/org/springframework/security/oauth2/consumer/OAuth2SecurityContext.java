package org.springframework.security.oauth2.consumer;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

/**
 * The OAuth 2 security context (for a specific user).
 *
 * @author Ryan Heaton
 */
public interface OAuth2SecurityContext {

  /**
   * Get the access tokens for the current context.
   *
   * @return The access tokens for the current context. The key to the map is the {@link OAuth2ProtectedResourceDetails#getId() id of the protected resource}
   * for which the access token is valid.
   */
  Map<String, OAuth2AccessToken> getAccessTokens();

  /**
   * Get the state that has been preserved for the current context.
   *
   * @return the state that has been preserved for the current context.
   */
  Object getPreservedState();

  /**
   * The URI to which a user is to be redirected after authorizing an access token request for this context.
   *
   * @return The URI to which a user is to be redirected after authorizing an access token request for this context.
   */
  String getUserAuthorizationRedirectUri();

  /**
   * The verification code for this context.
   *
   * @return The verification code, or null if none.
   */
  String getVerificationCode();

  /**
   * Any details for this security this context.
   *
   * @return Any details for this security context.
   */
  Object getDetails();

  /**
   * The error parameters associated with this context.
   *
   * @return The error parameters associated with this context.
   */
  Map<String, String> getErrorParameters();
}
