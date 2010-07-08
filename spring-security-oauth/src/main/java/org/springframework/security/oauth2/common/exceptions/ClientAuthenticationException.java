package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 *
 * @author Ryan Heaton
 */
public class ClientAuthenticationException extends OAuth2Exception {

  public ClientAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }

  public ClientAuthenticationException(String msg) {
    super(msg);
  }

  public ClientAuthenticationException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "incorrect_client_credentials";
  }
}
