package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * An OAuth 2 authentication token can contain multiple authentications: one for the client and one for
 * the user. Since some OAuth profiles don't require user authentication, the user authentication may be null.
 *
 * @author Ryan Heaton
 */
public class OAuth2Authentication<C extends Authentication, U extends Authentication> extends AbstractAuthenticationToken {

  private final C clientAuthentication;
  private final U userAuthentication;

  /**
   * Construct an OAuth 2 authentication. Since some OAuth profiles don't require user authentication, the user authentication may be null.
   *
   * @param clientAuthentication The client authentication (may NOT be null).
   * @param userAuthentication The user authentication (possibly null).
   */
  public OAuth2Authentication(C clientAuthentication, U userAuthentication) {
    super(userAuthentication == null ? clientAuthentication.getAuthorities() : userAuthentication.getAuthorities());
    this.clientAuthentication = clientAuthentication;
    this.userAuthentication = userAuthentication;
  }

  public Object getCredentials() {
    return this.userAuthentication == null ? this.clientAuthentication.getCredentials() : this.userAuthentication.getCredentials();
  }

  public Object getPrincipal() {
    return this.userAuthentication == null ? this.clientAuthentication.getPrincipal() : this.userAuthentication.getPrincipal();
  }

  /**
   * The client authentication.
   *
   * @return The client authentication.
   */
  public C getClientAuthentication() {
    return clientAuthentication;
  }

  /**
   * The user authentication.
   *
   * @return The user authentication.
   */
  public U getUserAuthentication() {
    return userAuthentication;
  }

  @Override
  public boolean isAuthenticated() {
    return this.clientAuthentication.isAuthenticated() && (this.userAuthentication == null || this.userAuthentication.isAuthenticated());
  }

}
