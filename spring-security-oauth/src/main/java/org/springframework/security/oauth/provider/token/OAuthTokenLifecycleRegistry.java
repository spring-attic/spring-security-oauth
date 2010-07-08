package org.springframework.security.oauth.provider.token;

import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collection;

/**
 * Interface for a registry of token lifecycle listeners.
 *
 * @author Ryan Heaton
 */
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