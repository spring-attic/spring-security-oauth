package org.springframework.security.oauth.common.signature;

/**
 * Marker interface for indicating that a consumer secret has some salt.
 *
 * @author Ryan Heaton
 */
public interface SaltedConsumerSecret {

  /**
   * Returns the salt to use for this consumer secret.
   *
   * @return the salt to use for this consumer secret.
   */
  Object getSalt();
}
