package org.springframework.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collections;
import java.util.List;

/**
 * Base POJO-based implementation of {@link org.springframework.security.oauth2.provider.ClientDetails}.
 *
 * @author Ryan Heaton
 */
public class BaseClientDetails implements ClientDetails {

  private String clientId;
  private String clientSecret;
  private List<String> scope;
  private List<String> authorizedGrantTypes;
  private String webServerRedirectUri;
  private List<GrantedAuthority> authorities = Collections.emptyList();

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public boolean isSecretRequired() {
    return this.clientSecret != null;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public boolean isScoped() {
    return this.scope != null && !this.scope.isEmpty();
  }

  public List<String> getScope() {
    return scope;
  }

  public void setScope(List<String> scope) {
    this.scope = scope;
  }

  public List<String> getAuthorizedGrantTypes() {
    return authorizedGrantTypes;
  }

  public void setAuthorizedGrantTypes(List<String> authorizedGrantTypes) {
    this.authorizedGrantTypes = authorizedGrantTypes;
  }

  public String getWebServerRedirectUri() {
    return webServerRedirectUri;
  }

  public void setWebServerRedirectUri(String webServerRedirectUri) {
    this.webServerRedirectUri = webServerRedirectUri;
  }

  public List<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(List<GrantedAuthority> authorities) {
    this.authorities = authorities;
  }
}
