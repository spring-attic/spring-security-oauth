package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
public class InvalidTokenException extends ClientAuthenticationException {

  public InvalidTokenException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidTokenException(String msg) {
    super(msg);
  }

  public InvalidTokenException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }
}
