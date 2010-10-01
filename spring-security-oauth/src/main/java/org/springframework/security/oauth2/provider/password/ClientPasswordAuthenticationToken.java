package org.springframework.security.oauth2.provider.password;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.Set;

/**
 * Authentication token used for containing OAuth 2 "Resource Owner Password Credentials" (see associated section of the OAuth 2 spec).
 *
 * @author Ryan Heaton
 */
public class ClientPasswordAuthenticationToken extends AbstractAuthenticationToken {

  private final ClientAuthenticationToken clientAuthentication;
  private final UsernamePasswordAuthenticationToken userAuthentication;

  public ClientPasswordAuthenticationToken(String clientId, String clientSecret, Set<String> scope, String username, String password) {
    super(null);
    this.clientAuthentication = new AccessGrantAuthenticationToken(clientId, clientSecret, scope, "password");
    this.userAuthentication = new UsernamePasswordAuthenticationToken(username, password);
  }

  public ClientAuthenticationToken getClientAuthentication() {
    return clientAuthentication;
  }

  public UsernamePasswordAuthenticationToken getUserAuthentication() {
    return userAuthentication;
  }

  public Object getPrincipal() {
    return this.userAuthentication.getPrincipal();
  }

  public Object getCredentials() {
    return this.userAuthentication.getCredentials();
  }

  @Override
  public void setDetails(Object details) {
    super.setDetails(details);
    this.clientAuthentication.setDetails(details);
    this.userAuthentication.setDetails(details);
  }
}
