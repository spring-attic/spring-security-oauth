package org.springframework.security.oauth2.common.exceptions;

import org.springframework.security.core.AuthenticationException;

import java.util.Map;

/**
 * Base exception for OAuth 2 authentication exceptions.
 * 
 * @author Ryan Heaton
 */
public class OAuth2Exception extends AuthenticationException {

  public OAuth2Exception(String msg, Throwable t) {
    super(msg, t);
  }

  public OAuth2Exception(String msg) {
    super(msg);
  }

  public OAuth2Exception(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  /**
   * The OAuth2 error code.
   *
   * @return The OAuth2 error code.
   */
  public String getOAuth2ErrorCode() {
    return "server_error";
  }

  /**
   * Get any additional information associated with this error.
   *
   * @return Additional information, or null if none.
   */
  public Map<String, String> getAdditionalInformation() {
    return null;
  }
}
