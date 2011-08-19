package org.springframework.security.oauth2.consumer.auth;

/**
 * Known schemes for client authentication.
 *
 * @author Ryan Heaton
 */
public enum ClientAuthenticationScheme {

  /**
   * HTTP Basic Auth scheme, per section 2.1 of the spec.
   */
  http_basic,

  /**
   * form parameter scheme, per section 2.1 of the spec.
   */
  form
}
