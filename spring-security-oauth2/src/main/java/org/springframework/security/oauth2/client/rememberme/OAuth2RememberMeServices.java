package org.springframework.security.oauth2.client.rememberme;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Services for "remembering" the access tokens that have been obtained.
 *
 * @author Ryan Heaton
 */
public interface OAuth2RememberMeServices {

  /**
   * Load any remembered tokens for the given request.
   *
   * @param request The request.
   * @param response The response.
   * @return The tokens (mapped by resource id), or null if none are remembered.
   */
  Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response);

  /**
   * Remember the specified tokens for the given request.
   *
   * @param tokens The tokens (null to forget all tokens).
   * @param request The request.
   * @param response The response.
   */
  void rememberTokens(Map<String, OAuth2AccessToken> tokens, HttpServletRequest request, HttpServletResponse response);

  /**
   * Load the preserved state for the given request.
   *
   * @param state The id the preserved state. Possibly null, in which case it indicates to load the global state, if any.
   * @param request The request.
   * @param response The response.
   * @return The preserved state (mapped by resource id), or null if none is remembered.
   */
  Object loadPreservedState(String state, HttpServletRequest request, HttpServletResponse response);

  /**
   * Preserve the specified state for the given resource.
   *
   * @param id The id state to preserve. Possibly null, in which case it indicates to load the global state, if any.
   * @param state The state to preserve.
   * @param request The request.
   * @param response The response.
   */
  void preserveState(String id, Object state, HttpServletRequest request, HttpServletResponse response);
}
