package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.Set;

/**
 * Authentication token for a request for a authorization code.
 *
 * @author Ryan Heaton
 */
public class UnconfirmedAuthorizationCodeAuthenticationToken extends ClientAuthenticationToken {

  private final String state;
  private final String requestedRedirect;
  private boolean denied;

  public UnconfirmedAuthorizationCodeAuthenticationToken(String clientId, Set<String> scope, String state, String requestedRedirect) {
    super(clientId, null, scope);
    this.state = state;
    this.requestedRedirect = requestedRedirect;
  }

  public String getRequestedRedirect() {
    return requestedRedirect;
  }

  public String getState() {
    return state;
  }

  public boolean isDenied() {
    return denied;
  }

  public void setDenied(boolean denied) {
    this.denied = denied;
    setAuthenticated(!denied);
  }
}