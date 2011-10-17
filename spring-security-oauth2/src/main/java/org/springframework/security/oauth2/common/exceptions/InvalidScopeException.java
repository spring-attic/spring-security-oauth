package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class InvalidScopeException extends OAuth2Exception {

  public InvalidScopeException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidScopeException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_scope";
  }
}