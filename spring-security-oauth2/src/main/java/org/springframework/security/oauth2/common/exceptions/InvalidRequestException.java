package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Dave Syer
 */
public class InvalidRequestException extends ClientAuthenticationException {

  public InvalidRequestException(String msg, Throwable t) {
    super(msg, t);
  }

  public InvalidRequestException(String msg) {
    super(msg);
  }

  public InvalidRequestException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_request";
  }
}
