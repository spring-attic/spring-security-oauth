package org.springframework.security.oauth2.consumer;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class OAuth2SecurityContextImpl implements OAuth2SecurityContext {

  private Map<String, OAuth2AccessToken> accessTokens;
  private Object preservedState;
  private String userAuthorizationRedirectUri;
  private String error;
  private String verificationCode;
  private Object details;

  public Map<String, OAuth2AccessToken> getAccessTokens() {
    return accessTokens;
  }

  public void setAccessTokens(Map<String, OAuth2AccessToken> accessTokens) {
    this.accessTokens = accessTokens;
  }

  public Object getPreservedState() {
    return preservedState;
  }

  public void setPreservedState(Object preservedState) {
    this.preservedState = preservedState;
  }

  public String getUserAuthorizationRedirectUri() {
    return userAuthorizationRedirectUri;
  }

  public void setUserAuthorizationRedirectUri(String userAuthorizationRedirectUri) {
    this.userAuthorizationRedirectUri = userAuthorizationRedirectUri;
  }

  public String getError() {
    return error;
  }

  public void setError(String error) {
    this.error = error;
  }

  public String getVerificationCode() {
    return verificationCode;
  }

  public void setVerificationCode(String verificationCode) {
    this.verificationCode = verificationCode;
  }

  public Object getDetails() {
    return details;
  }

  public void setDetails(Object details) {
    this.details = details;
  }
}
