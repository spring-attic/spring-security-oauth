package org.springframework.security.oauth.consumer.rememberme;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Services for "remembering" the access tokens that have been obtained.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
public interface OAuthRememberMeServices {

  /**
   * Load any remembered tokens for the given request.
   *
   * @param request The request.
   * @param response The response.
   * @return The tokens (mapped by resource id), or null if none are remembered.
   */
  Map<String, OAuthConsumerToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response);

  /**
   * Remember the specified tokens for the given request.
   *
   * @param tokens The tokens (null to forget all tokens).
   * @param request The request.
   * @param response The response.
   */
  void rememberTokens(Map<String, OAuthConsumerToken> tokens, HttpServletRequest request, HttpServletResponse response);

}
