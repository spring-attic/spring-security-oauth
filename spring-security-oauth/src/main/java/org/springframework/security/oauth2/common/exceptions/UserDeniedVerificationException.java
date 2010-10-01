package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class UserDeniedVerificationException extends OAuth2Exception {

  public UserDeniedVerificationException(String msg, Throwable t) {
    super(msg, t);
  }

  public UserDeniedVerificationException(String msg) {
    super(msg);
  }

  public UserDeniedVerificationException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "access_denied";
  }

}
