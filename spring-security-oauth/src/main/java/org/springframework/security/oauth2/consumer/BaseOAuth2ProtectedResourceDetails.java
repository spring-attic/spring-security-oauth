package org.springframework.security.oauth2.consumer;

import java.util.List;

/**
 * @author Ryan Heaton
 */
public class BaseOAuth2ProtectedResourceDetails implements OAuth2ProtectedResourceDetails {

  private String id;
  private String flowType;
  private String clientId;
  private String accessTokenUri;
  private boolean scoped;
  private List<String> scope;
  private boolean secretRequired;
  private String clientSecret;
  private BearerTokenMethod bearerTokenMethod = BearerTokenMethod.header;

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
    return false;
  }

  public String getClientSecret() {
    return null;
  }

  public BearerTokenMethod getBearerTokenMethod() {
    return bearerTokenMethod;
  }

  public void setBearerTokenMethod(BearerTokenMethod bearerTokenMethod) {
    this.bearerTokenMethod = bearerTokenMethod;
  }

  public String getFlowType() {
    return flowType;
  }

  public void setFlowType(String flowType) {
    this.flowType = flowType;
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
