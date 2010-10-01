package org.springframework.security.oauth2.common.exceptions;

/**
 * Base exception
 *
 * @author Ryan Heaton
 */
public abstract class ClientAuthenticationException extends OAuth2Exception {

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
  public int getHttpErrorCode() {
    return 401;
  }

  @Override
  public abstract String getOAuth2ErrorCode();
}
