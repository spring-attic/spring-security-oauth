package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthenticationException;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Default implementation for a redirect resolver.
 *
 * @author Ryan Heaton
 */
public class DefaultRedirectResolver implements RedirectResolver {

  public String resolveRedirect(String requestedRedirect, ClientDetails client) {
    String redirectUri = client.getWebServerRedirectUri();
    if (redirectUri != null && requestedRedirect != null && !redirectMatches(requestedRedirect, redirectUri)) {
      throw new UserDeniedAuthenticationException("Invalid redirect (must be " + redirectUri + ").");
    }

    if (redirectUri == null) {
      if (requestedRedirect == null) {
        throw new UserDeniedAuthenticationException("A redirect_uri must be supplied.");
      }
      redirectUri = requestedRedirect;
    }

    return redirectUri;
  }

  /**
   * Whether the requested redirect URI "matches" the specified redirect URI. Default implementation tests equality.
   *
   * @param requestedRedirect The requestesd redirect URI.
   * @param redirectUri The client-specified redirect URI.
   * @return Whether the requested redirect URI "matches" the specified redirect URI.
   */
  protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
    return requestedRedirect.equals(redirectUri);
  }
}
