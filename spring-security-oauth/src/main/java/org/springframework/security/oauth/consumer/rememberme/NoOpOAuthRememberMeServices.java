package org.springframework.security.oauth.consumer.rememberme;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Basic, no-op implementation of the remember-me services.
 * 
 * @author Ryan Heaton
 */
public class NoOpOAuthRememberMeServices implements OAuthRememberMeServices {

  public Map<String, OAuthConsumerToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
    return null;
  }

  public void rememberTokens(Map<String, OAuthConsumerToken> tokens, HttpServletRequest request, HttpServletResponse response) {
  }

}
