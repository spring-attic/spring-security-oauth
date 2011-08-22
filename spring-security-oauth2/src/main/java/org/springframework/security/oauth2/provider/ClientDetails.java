package org.springframework.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.List;

/**
 * Consumer details for OAuth 2
 *
 * @author Ryan Heaton
 */
public interface ClientDetails extends Serializable {

  /**
   * The client id.
   *
   * @return The client id.
   */
  String getClientId();

  /**
   * The resources that this client can access. Ignored if empty.
   *
   * @return The resources of this client.
   */
  List<String> getResourceIds();

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
   * The grant types for which this client is authorized.
   *
   * @return The grant types for which this client is authorized.
   */
  List<String> getAuthorizedGrantTypes();

  /**
   * The pre-defined redirect URI for this client to use during the "authorization_code" access grant. See OAuth spec, section 4.1.1.
   *
   * @return The pre-defined redirect URI for this client.
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
