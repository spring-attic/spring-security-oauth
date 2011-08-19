package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 *
 * @author Ryan Heaton
 */
public class UnauthorizedClientException extends ClientAuthenticationException {

  public UnauthorizedClientException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnauthorizedClientException(String msg) {
    super(msg);
  }

  public UnauthorizedClientException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unauthorized_client";
  }
}
