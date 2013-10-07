package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class UnsupportedGrantTypeException extends OAuth2Exception {

  public UnsupportedGrantTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedGrantTypeException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unsupported_grant_type";
  }
}