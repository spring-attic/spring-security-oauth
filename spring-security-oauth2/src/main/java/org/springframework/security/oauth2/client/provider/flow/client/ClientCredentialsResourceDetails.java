package org.springframework.security.oauth2.client.provider.flow.client;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 */
public class ClientCredentialsResourceDetails extends BaseOAuth2ProtectedResourceDetails {

  private String preEstablishedRedirectUri;

  public ClientCredentialsResourceDetails() {
    setGrantType("client_credentials");
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
