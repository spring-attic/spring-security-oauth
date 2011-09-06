package org.springframework.security.oauth2.client.rememberme;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Basic, no-op implementation of the remember-me services.
 * 
 * @author Ryan Heaton
 */
public class NoOpOAuth2RememberMeServices implements OAuth2RememberMeServices {

  public Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
    return null;
  }

  public void rememberTokens(Map<String, OAuth2AccessToken> tokens, HttpServletRequest request, HttpServletResponse response) {
  }

  public Object loadPreservedState(String state, HttpServletRequest request, HttpServletResponse response) {
    return null;
  }

  public void preserveState(String id, Object state, HttpServletRequest request, HttpServletResponse response) {
  }
}
