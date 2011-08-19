package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 *
 * @author Ryan Heaton
 */
public class InvalidClientException extends ClientAuthenticationException {

  public InvalidClientException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidClientException(String msg) {
    super(msg);
  }

  public InvalidClientException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_client";
  }
}
