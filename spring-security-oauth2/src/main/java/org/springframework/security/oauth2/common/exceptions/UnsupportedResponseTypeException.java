package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class UnsupportedResponseTypeException extends OAuth2Exception {

  public UnsupportedResponseTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedResponseTypeException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unsupported_response_type";
  }
}