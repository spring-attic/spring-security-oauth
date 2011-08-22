package org.springframework.security.oauth.consumer;


import java.util.Map;

/**
 * The OAuth 2 security context (for a specific user).
 *
 * @author Ryan Heaton
 */
public interface OAuthSecurityContext {

  /**
   * Get the access tokens for the current context.
   *
   * @return The access tokens for the current context. The key to the map is the {@link ProtectedResourceDetails#getId() id of the protected resource}
   * for which the access token is valid.
   */
  Map<String, OAuthConsumerToken> getAccessTokens();

  /**
   * Any details for this security this context.
   *
   * @return Any details for this security context.
   */
  Object getDetails();

}
