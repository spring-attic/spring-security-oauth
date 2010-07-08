package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class InvalidVerificationCodeException extends ClientAuthenticationException {

  public InvalidVerificationCodeException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidVerificationCodeException(String msg) {
    super(msg);
  }

  public InvalidVerificationCodeException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "bad_verification_code";
  }
}