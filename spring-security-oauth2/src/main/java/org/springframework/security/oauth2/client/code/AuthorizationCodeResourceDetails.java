package org.springframework.security.oauth2.client.code;

import org.springframework.security.oauth2.client.provider.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Ryan Heaton
 */
public class AuthorizationCodeResourceDetails extends BaseOAuth2ProtectedResourceDetails {

  private String userAuthorizationUri;
  private String state;
  private String preEstablishedRedirectUri;

  public AuthorizationCodeResourceDetails() {
    setGrantType("authorization_code");
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
