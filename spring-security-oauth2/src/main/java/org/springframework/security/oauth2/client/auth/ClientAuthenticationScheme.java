package org.springframework.security.oauth2.client.auth;

/**
 * Known schemes for client authentication.
 *
 * @author Ryan Heaton
 */
public enum ClientAuthenticationScheme {

  /**
   * HTTP Basic Auth scheme, per section 2 of the spec.
   */
  http_basic,

  /**
   * form parameter scheme, per section 2 of the spec.
   */
  form
}
