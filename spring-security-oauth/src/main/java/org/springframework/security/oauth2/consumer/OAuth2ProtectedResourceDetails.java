package org.springframework.security.oauth2.consumer;

import java.util.List;

/**
 * Details for an OAuth2-protected resource.
 *
 * @author Ryan Heaton
 */
public interface OAuth2ProtectedResourceDetails {

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
   * The flow type of this resource.
   *
   * @return The flow type of this resource.
   */
  String getFlowType();

}
