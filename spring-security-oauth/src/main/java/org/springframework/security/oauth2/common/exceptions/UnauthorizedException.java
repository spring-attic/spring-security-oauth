package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class UnauthorizedException extends ClientAuthenticationException {

  public UnauthorizedException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnauthorizedException(String msg) {
    super(msg);
  }

  public UnauthorizedException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unauthorized";
  }

}
