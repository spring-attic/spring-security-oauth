package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 *
 * @author Ryan Heaton
 */
public class UnsupportedOAuthFlowTypeException extends OAuth2Exception {

  public UnsupportedOAuthFlowTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedOAuthFlowTypeException(String msg) {
    super(msg);
  }

  public UnsupportedOAuthFlowTypeException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unauthorized_client";
  }
}