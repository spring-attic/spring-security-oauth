package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class InvalidSignatureException extends ClientAuthenticationException {

  public InvalidSignatureException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidSignatureException(String msg) {
    super(msg);
  }

  public InvalidSignatureException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_signature";
  }
}
