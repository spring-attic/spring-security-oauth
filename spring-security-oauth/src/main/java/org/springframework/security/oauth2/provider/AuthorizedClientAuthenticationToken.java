package org.springframework.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Set;

/**
 * Authentication token for an authorized client.
 * 
 * @author Ryan Heaton
 */
public class AuthorizedClientAuthenticationToken extends ClientAuthenticationToken {

  public AuthorizedClientAuthenticationToken(String clientId, String clientSecret, Set<String> scope, Collection<GrantedAuthority> authorities) {
    super(clientId, clientSecret, scope, authorities);
  }

}
