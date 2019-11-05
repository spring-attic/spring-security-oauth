package org.springframework.security.oauth.consumer;

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
@Deprecated
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
