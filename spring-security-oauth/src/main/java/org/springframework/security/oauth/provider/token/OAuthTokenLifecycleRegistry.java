package org.springframework.security.oauth.provider.token;

import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collection;

/**
 * Interface for a registry of token lifecycle listeners.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
public interface OAuthTokenLifecycleRegistry {

  /**
   * The collection of lifecycle listeners for this registry.
   *
   * @return The collection of lifecycle listeners for this registry.
   */
  Collection<OAuthTokenLifecycleListener> getLifecycleListeners();

  /**
   * Register lifecycle listener(s) with this registry.
   *
   * @param lifecycleListeners The listeners.
   */
  @Autowired ( required = false )
  void register(OAuthTokenLifecycleListener... lifecycleListeners);
}