package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class UnsupportedResponseTypeException extends OAuth2Exception {

  public UnsupportedResponseTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedResponseTypeException(String msg) {
    super(msg);
  }

  public UnsupportedResponseTypeException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unsupported_response_type";
  }
}