package org.springframework.security.oauth2.client.filter;

import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class OAuth2ClientContextImpl implements OAuth2ClientContext {

  private Map<String, OAuth2AccessToken> accessTokens;
  private Object preservedState;
  private String userAuthorizationRedirectUri;
  private Map<String, String> errorParameters;
  private String authorizationCode;
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

  public Map<String, String> getErrorParameters() {
    return errorParameters;
  }

  public void setErrorParameters(Map<String, String> errorParameters) {
    this.errorParameters = errorParameters;
  }

  public String getAuthorizationCode() {
    return authorizationCode;
  }

  public void setAuthorizationCode(String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  public Object getDetails() {
    return details;
  }

  public void setDetails(Object details) {
    this.details = details;
  }
}
