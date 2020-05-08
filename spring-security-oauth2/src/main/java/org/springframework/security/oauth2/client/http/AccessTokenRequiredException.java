package org.springframework.security.oauth2.client.http;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
@Deprecated
public class AccessTokenRequiredException extends InsufficientAuthenticationException {

  private final OAuth2ProtectedResourceDetails resource;

  public AccessTokenRequiredException(OAuth2ProtectedResourceDetails resource) {
    super("OAuth2 access denied.");
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource) {
    super(msg);
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
    super(msg, t);
    this.resource = resource;
  }

  public OAuth2ProtectedResourceDetails getResource() {
    return resource;
  }
}
