package org.springframework.security.oauth2.common.exceptions;

import org.springframework.security.core.AuthenticationException;

import java.util.Map;
import java.util.TreeMap;

/**
 * Base exception for OAuth 2 authentication exceptions.
 * 
 * @author Ryan Heaton
 */
public class OAuth2Exception extends AuthenticationException {

  private Map<String, String> additionalInformation = null;

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
    return "invalid_request";
  }

  /**
   * The HTTP error code associated with this error.
   *
   * @return The HTTP error code associated with this error.
   */
  public int getHttpErrorCode() {
    return 400;
  }

  /**
   * Get any additional information associated with this error.
   *
   * @return Additional information, or null if none.
   */
  public Map<String, String> getAdditionalInformation() {
    return this.additionalInformation;
  }

  /**
   * Add some additional information with this OAuth error.
   *
   * @param key The key.
   * @param value The value.
   */
  public void addAdditionalInformation(String key, String value) {
    if (this.additionalInformation == null) {
      this.additionalInformation = new TreeMap<String, String>();
    }

    this.additionalInformation.put(key, value);

  }
}
