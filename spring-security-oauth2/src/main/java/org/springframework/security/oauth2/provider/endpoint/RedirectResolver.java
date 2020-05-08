package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Basic interface for determining the redirect URI for a user agent.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@Deprecated
public interface RedirectResolver {

  /**
   * Resolve the redirect for the specified client.
   *
   * @param requestedRedirect The redirect that was requested (may not be null).
   * @param client The client for which we're resolving the redirect.
   * @return The resolved redirect URI.
   * @throws OAuth2Exception If the requested redirect is invalid for the specified client.
   */
  String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception;

}
