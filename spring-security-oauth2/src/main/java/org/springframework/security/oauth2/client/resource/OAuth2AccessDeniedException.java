package org.springframework.security.oauth2.client.resource;

import org.springframework.security.access.AccessDeniedException;

/**
 * @author Ryan Heaton
 */
public class OAuth2AccessDeniedException extends AccessDeniedException {

  private OAuth2ProtectedResourceDetails resource;

  public OAuth2AccessDeniedException() {
    super("OAuth2 access denied.");
  }

  public OAuth2AccessDeniedException(String msg) {
    super(msg);
  }

  public OAuth2AccessDeniedException(OAuth2ProtectedResourceDetails resource) {
    super("OAuth2 access denied.");
    this.resource = resource;
  }

  public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource) {
    super(msg);
    this.resource = resource;
  }

  public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
    super(msg, t);
    this.resource = resource;
  }

  public OAuth2ProtectedResourceDetails getResource() {
    return resource;
  }

  public void setResource(OAuth2ProtectedResourceDetails resource) {
    this.resource = resource;
  }
}
