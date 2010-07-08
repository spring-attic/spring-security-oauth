package org.springframework.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;

/**
 * Consumer details for OAuth 2
 *
 * @author Ryan Heaton
 */
public interface ClientDetails {

  /**
   * The client id.
   *
   * @return The client id.
   */
  String getClientId();

  /**
   * Whether a secret is required to authenticate this client.
   *
   * @return Whether a secret is required to authenticate this client.
   */
  boolean isSecretRequired();

  /**
   * The client secret. Ignored if the {@link #isSecretRequired() secret isn't required}.
   *
   * @return The client secret.
   */
  String getClientSecret();

  /**
   * Whether this client is limited to a specific scope. If false, the scope of the authentication request will
   * be ignored.
   *
   * @return Whether this client is limited to a specific scope.
   */
  boolean isScoped();

  /**
   * The scope of this client. Ignored if the {@link #isScoped() client isn't scoped}.
   *
   * @return The scope of this client.
   */
  List<String> getScope();

  /**
   * The flows for which this client is authorized.
   *
   * @return The flows for which this client is authorized.
   */
  List<String> getAuthorizedFlows();

  /**
   * The redirect URI for this client during the "web_server" flow. Return null if the redirect uri isn't specified. This value is ignored if the
   * "web_server" flow isn't supported by this client.
   *
   * @return The redirect URI for this client during the "web_server" flow.
   */
  String getWebServerRedirectUri();

  /**
   * Get the authorities that are granted to the OAuth client.  Note that these are NOT the authorities
   * that are granted to the client with a user-authorized access token. Instead, these authorities are
   * inherent to the client itself.
   *
   * @return The authorities.
   */
  List<GrantedAuthority> getAuthorities();
}
