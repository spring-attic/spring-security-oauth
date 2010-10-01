package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class ExpiredTokenException extends ClientAuthenticationException {

  public ExpiredTokenException(String msg, Throwable t) {
    super(msg, t);
  }

  public ExpiredTokenException(String msg) {
    super(msg);
  }

  public ExpiredTokenException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "expired_token";
  }
}
