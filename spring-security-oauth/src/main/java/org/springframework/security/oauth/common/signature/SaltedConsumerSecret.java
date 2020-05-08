package org.springframework.security.oauth.common.signature;

/**
 * Marker interface for indicating that a consumer secret has some salt.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
public interface SaltedConsumerSecret {

  /**
   * Returns the salt to use for this consumer secret.
   *
   * @return the salt to use for this consumer secret.
   */
  Object getSalt();
}
