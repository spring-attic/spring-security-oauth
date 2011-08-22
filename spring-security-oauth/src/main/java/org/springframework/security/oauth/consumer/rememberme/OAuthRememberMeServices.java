package org.springframework.security.oauth.consumer.rememberme;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Services for "remembering" the access tokens that have been obtained.
 *
 * @author Ryan Heaton
 */
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
