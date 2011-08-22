package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * An OAuth 2 authentication token can contain multiple authentications: one for the client and one for
 * the user. Since some OAuth profiles don't require user authentication, the user authentication may be null.
 *
 * @author Ryan Heaton
 */
public class OAuth2Authentication<C extends ClientAuthenticationToken, U extends Authentication> extends AbstractAuthenticationToken {

  private static final long serialVersionUID = -4809832298438307309L;

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

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof OAuth2Authentication)) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    OAuth2Authentication that = (OAuth2Authentication) o;

    if (!clientAuthentication.equals(that.clientAuthentication)) {
      return false;
    }
    if (userAuthentication != null ? !userAuthentication.equals(that.userAuthentication) : that.userAuthentication != null) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + clientAuthentication.hashCode();
    result = 31 * result + (userAuthentication != null ? userAuthentication.hashCode() : 0);
    return result;
  }
}
