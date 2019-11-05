package org.springframework.security.oauth.provider.token;

/**
 * Interface for listening to the lifecycle of a token.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
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
