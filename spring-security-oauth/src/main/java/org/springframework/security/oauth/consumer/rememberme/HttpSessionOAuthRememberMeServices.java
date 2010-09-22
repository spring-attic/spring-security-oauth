package org.springframework.security.oauth.consumer.rememberme;

import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * Default implementation of the OAuth2 rememberme services. Just stores everything in the session.
 * 
 * @author Ryan Heaton
 */
public class HttpSessionOAuthRememberMeServices implements OAuthRememberMeServices {

  public static final String REMEMBERED_TOKENS_KEY = HttpSessionOAuthRememberMeServices.class.getName() + "#REMEMBERED_TOKENS";

  public Map<String, OAuthConsumerToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession(false);
    Map<String, OAuthConsumerToken> rememberedTokens = null;
    if (session != null) {
      rememberedTokens = (Map<String, OAuthConsumerToken>) session.getAttribute(REMEMBERED_TOKENS_KEY);
    }
    return rememberedTokens;
  }

  public void rememberTokens(Map<String, OAuthConsumerToken> tokens, HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession(false);
    if (session != null) {
      session.setAttribute(REMEMBERED_TOKENS_KEY, tokens);
    }
  }
}
