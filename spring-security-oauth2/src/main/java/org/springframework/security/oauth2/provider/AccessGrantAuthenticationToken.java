package org.springframework.security.oauth2.provider;

import java.util.Set;

/**
 * Authentication credentials for an access grant for an authorized token.
 * 
 * @author Ryan Heaton
 */
public class AccessGrantAuthenticationToken extends ClientAuthenticationToken {

  private final String grantType;

  public AccessGrantAuthenticationToken(String clientId, String clientSecret, Set<String> scope, String grantType) {
    super(clientId, clientSecret, scope);
    this.grantType = grantType;
  }

  /**
   * The type of the grant.
   *
   * @return The type of the grant.
   */
  public String getGrantType() {
    return grantType;
  }
}
