package org.springframework.security.oauth2.consumer.webserver;

import org.springframework.security.oauth2.consumer.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Ryan Heaton
 */
public class WebServerFlowResourceDetails extends BaseOAuth2ProtectedResourceDetails {

  private String userAuthorizationUri;
  private String state;
  private boolean requireImmediateAuthorization;
  private String preEstablishedRedirectUri;

  public WebServerFlowResourceDetails() {
    setFlowType("web_server");
  }

  /**
   * The id of the state of the flow, if any.
   *
   * @return The id of the state of the flow, if any.
   */
  public String getState() {
    return state;
  }

  /**
   * The id of the state of the flow, if any.
   *
   * @param state The id of the state of the flow, if any.
   */
  public void setState(String state) {
    this.state = state;
  }

  /**
   * The URI to which the user is to be redirected to authorize an access token.
   *
   * @return The URI to which the user is to be redirected to authorize an access token.
   */
  public String getUserAuthorizationUri() {
    return userAuthorizationUri;
  }

  /**
   * The URI to which the user is to be redirected to authorize an access token.
   *
   * @param userAuthorizationUri The URI to which the user is to be redirected to authorize an access token.
   */
  public void setUserAuthorizationUri(String userAuthorizationUri) {
    this.userAuthorizationUri = userAuthorizationUri;
  }

  /**
   * Whether the authorization server is to require an immediate authorization response.
   *
   * @return Whether the authorization server is to require an immediate authorization response.
   */
  public boolean isRequireImmediateAuthorization() {
    return requireImmediateAuthorization;
  }

  /**
   * Whether the authorization server is to require an immediate authorization response.
   *
   * @param requireImmediateAuthorization Whether the authorization server is to require an immediate authorization response.
   */
  public void setRequireImmediateAuthorization(boolean requireImmediateAuthorization) {
    this.requireImmediateAuthorization = requireImmediateAuthorization;
  }

  /**
   * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from the user authorization request
   * because the server doesn't need to know it.
   *
   * @return The redirect URI that has been pre-established with the server.
   */
  public String getPreEstablishedRedirectUri() {
    return preEstablishedRedirectUri;
  }

  /**
   * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from the user authorization request
   * because the server doesn't need to know it.
   *
   * @param preEstablishedRedirectUri The redirect URI that has been pre-established with the server.
   */
  public void setPreEstablishedRedirectUri(String preEstablishedRedirectUri) {
    this.preEstablishedRedirectUri = preEstablishedRedirectUri;
  }
}
