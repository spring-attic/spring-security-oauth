package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class RedirectMismatchException extends ClientAuthenticationException {

  public RedirectMismatchException(String msg, Throwable t) {
    super(msg, t);
  }

  public RedirectMismatchException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_grant";
  }
}
