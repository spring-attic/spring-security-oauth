package org.springframework.security.oauth2.provider.verification;

import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.Set;

/**
 * Authentication token for a request for authorization of a verification code.
 *
 * @author Ryan Heaton
 */
public class AuthorizationCodeAuthenticationToken extends ClientAuthenticationToken {

  private final String verificationCode;
  private final String requestedRedirect;

  public AuthorizationCodeAuthenticationToken(String clientId, String clientSecret, Set<String> scope, String verificationCode, String requestedRedirect) {
    super(clientId, clientSecret, scope);
    this.verificationCode = verificationCode;
    this.requestedRedirect = requestedRedirect;
  }

  public String getVerificationCode() {
    return verificationCode;
  }

  public String getRequestedRedirect() {
    return requestedRedirect;
  }
}