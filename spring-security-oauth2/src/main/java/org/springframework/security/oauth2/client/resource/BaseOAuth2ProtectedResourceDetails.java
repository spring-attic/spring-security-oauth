package org.springframework.security.oauth2.client.resource;

import java.util.List;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Ryan Heaton
 */
public class BaseOAuth2ProtectedResourceDetails implements OAuth2ProtectedResourceDetails {

  private String id;
  private String grantType = "authorization_code";
  private String clientId;
  private String accessTokenUri;
  private boolean scoped;
  private List<String> scope;
  private boolean secretRequired;
  private String clientSecret;
  private String clientAuthenticationScheme = ClientAuthenticationScheme.http_basic.toString();
  private BearerTokenMethod bearerTokenMethod = BearerTokenMethod.header;
  private String bearerTokenName = OAuth2AccessToken.BEARER_TYPE_PARAMETER;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getAccessTokenUri() {
    return accessTokenUri;
  }

  public void setAccessTokenUri(String accessTokenUri) {
    this.accessTokenUri = accessTokenUri;
  }

  public boolean isScoped() {
    return scoped;
  }

  public void setScoped(boolean scoped) {
    this.scoped = scoped;
  }

  public List<String> getScope() {
    return scope;
  }

  public void setScope(List<String> scope) {
    this.scope = scope;
  }

  public boolean isSecretRequired() {
    return secretRequired;
  }

  public void setSecretRequired(boolean secretRequired) {
    this.secretRequired = secretRequired;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getClientAuthenticationScheme() {
    return clientAuthenticationScheme;
  }

  public void setClientAuthenticationScheme(String clientAuthenticationScheme) {
    this.clientAuthenticationScheme = clientAuthenticationScheme;
  }

  public BearerTokenMethod getBearerTokenMethod() {
    return bearerTokenMethod;
  }

  public void setBearerTokenMethod(BearerTokenMethod bearerTokenMethod) {
    this.bearerTokenMethod = bearerTokenMethod;
  }

  public String getBearerTokenName() {
    return bearerTokenName;
  }

  public void setBearerTokenName(String bearerTokenName) {
    this.bearerTokenName = bearerTokenName;
  }

  public String getGrantType() {
    return grantType;
  }

  public void setGrantType(String grantType) {
    this.grantType = grantType;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof BaseOAuth2ProtectedResourceDetails)) {
      return false;
    }

    BaseOAuth2ProtectedResourceDetails that = (BaseOAuth2ProtectedResourceDetails) o;
    return !(id != null ? !id.equals(that.id) : that.id != null);

  }

  @Override
  public int hashCode() {
    return id != null ? id.hashCode() : 0;
  }

}
