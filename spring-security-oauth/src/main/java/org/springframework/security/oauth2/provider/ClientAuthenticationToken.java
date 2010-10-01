package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Set;

/**
 * Base class for client authentication requests.
 *
 * @author Ryan Heaton
 */
public abstract class ClientAuthenticationToken extends AbstractAuthenticationToken {

  private final String clientId;
  private final String clientSecret;
  private final Set<String> scope;

  protected ClientAuthenticationToken(String clientId, String clientSecret, Set<String> scope) {
    super(null);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scope = scope;
  }

  /**
   * Construct an <em>authenticated</em> token from an unauthenticated token.
   *
   * @param clientId The client id.
   * @param clientSecret The client secret.
   * @param scope The scope of the client authorities.
   * @param authorities The authorities granted.
   */
  protected ClientAuthenticationToken(String clientId, String clientSecret, Set<String> scope, Collection<GrantedAuthority> authorities) {
    super(authorities);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scope = scope;
    setAuthenticated(true);
  }

  public String getClientId() {
    return this.clientId;
  }

  public Object getPrincipal() {
    return getClientId();
  }

  public String getClientSecret() {
    return this.clientSecret;
  }

  public Object getCredentials() {
    return getClientSecret();
  }

  public Set<String> getScope() {
    return this.scope;
  }

}