package org.springframework.security.oauth.consumer;

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class AccessTokenRequiredException extends InsufficientAuthenticationException {

  private final ProtectedResourceDetails resource;

  public AccessTokenRequiredException(ProtectedResourceDetails resource) {
    super("OAuth access denied.");
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, ProtectedResourceDetails resource) {
    super(msg);
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, ProtectedResourceDetails resource, Throwable t) {
    super(msg, t);
    this.resource = resource;
  }

  public ProtectedResourceDetails getResource() {
    return resource;
  }
}
