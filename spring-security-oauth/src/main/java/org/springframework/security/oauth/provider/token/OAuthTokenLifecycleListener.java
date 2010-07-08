package org.springframework.security.oauth.provider.token;

/**
 * Interface for listening to the lifecycle of a token.
 *
 * @author Ryan Heaton
 */
public interface OAuthTokenLifecycleListener {

  /**
   * Lifecycle event for a created token.
   *
   * @param token The created token.
   */
  void tokenCreated(OAuthProviderToken token);

  /**
   * Lifecycle event for an expired token.
   *
   * @param token The expired token.
   */
  void tokenExpired(OAuthProviderToken token);


}
