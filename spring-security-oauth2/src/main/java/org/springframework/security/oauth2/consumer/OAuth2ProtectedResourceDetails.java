package org.springframework.security.oauth2.consumer;

import java.util.List;

/**
 * Details for an OAuth2-protected resource.
 *
 * @author Ryan Heaton
 */
public interface OAuth2ProtectedResourceDetails {

  /**
   * Enumeration of possible methods for bearing the access token for this resource.
   */
  public enum BearerTokenMethod {

    /**
     * Bear the token in an Authorization header.
     */
    header,

    /**
     * Bear the token in a query parameter in the URI.
     */
    query,

    /**
     * Bear the token in the form body.
     */
    form
  }

  /**
   * Get a unique identifier for these protected resource details.
   *
   * @return A unique identifier for these protected resource details.
   */
  public String getId();

  /**
   * The client identifier to use for this protected resource.
   *
   * @return The client identifier to use for this protected resource.
   */
  public String getClientId();

  /**
   * The URL to use to obtain an OAuth2 access token.
   *
   * @return The URL to use to obtain an OAuth2 access token.
   */
  String getAccessTokenUri();

  /**
   * Whether this resource is limited to a specific scope. If false, the scope of the authentication request will
   * be ignored.
   *
   * @return Whether this resource is limited to a specific scope.
   */
  boolean isScoped();

  /**
   * The scope of this resource. Ignored if the {@link #isScoped() resource isn't scoped}.
   *
   * @return The scope of this resource.
   */
  List<String> getScope();

  /**
   * Whether a secret is required to obtain an access token to this resource.
   *
   * @return Whether a secret is required to obtain an access token to this resource.
   */
  boolean isSecretRequired();

  /**
   * The client secret. Ignored if the {@link #isSecretRequired() secret isn't required}.
   *
   * @return The client secret.
   */
  String getClientSecret();

  /**
   * The scheme to use to authenticate the client. E.g. "header" or "query".
   *
   * @return The scheme used to authenticate the client.
   */
  String getClientAuthenticationScheme();

  /**
   * The grant type for obtaining an acces token for this resource.
   *
   * @return The grant type for obtaining an acces token for this resource.
   */
  String getGrantType();

  /**
   * Get the bearer token method for this resource.
   *
   * @return The bearer token method for this resource.
   */
  BearerTokenMethod getBearerTokenMethod();

  /**
   * The name of the bearer token. The default is "bearer_token", which is according to the spec, but some providers (e.g. Facebook) don't conform to the spec.)
   *
   * @return The name of the bearer token.
   */
  String getBearerTokenName();
}
