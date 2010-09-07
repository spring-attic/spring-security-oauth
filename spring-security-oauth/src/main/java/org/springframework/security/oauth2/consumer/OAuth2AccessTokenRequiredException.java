package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;

/**
 * @author Ryan Heaton
 */
public class OAuth2AccessTokenRequiredException extends AccessDeniedException {

  private final OAuth2ProtectedResourceDetails resource;

  public OAuth2AccessTokenRequiredException(OAuth2ProtectedResourceDetails resource) {
    super("OAuth2 access denied.");
    this.resource = resource;
  }

  public OAuth2AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource) {
    super(msg);
    this.resource = resource;
  }

  public OAuth2AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
    super(msg, t);
    this.resource = resource;
  }
}
