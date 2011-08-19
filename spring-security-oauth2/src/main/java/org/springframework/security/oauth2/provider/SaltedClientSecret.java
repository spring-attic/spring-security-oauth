package org.springframework.security.oauth2.provider;

/**
 * Marker interface for indicating that a client details secret has some salt.
 */
public interface SaltedClientSecret {

  /**
   * Returns the salt to use for this client secret.
   *
   * @return the salt to use for this client secret.
   */
  Object getSalt();
}
