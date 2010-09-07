package org.springframework.security.oauth2.consumer.rememberme;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.OAuth2ProtectedResourceDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class DefaultOAuth2RememberMeServices implements OAuth2RememberMeServices {

  public Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
    return null;
  }

  public void rememberTokens(Map<String, OAuth2AccessToken> tokens, HttpServletRequest request, HttpServletResponse response) {
  }

  public String loadRememberedRedirectUri(String scope) {
    return null;
  }

  public String rememberRedirectUri(HttpServletRequest request, HttpServletResponse response, OAuth2ProtectedResourceDetails resource, String redirectUri) {
    return null;
  }
}
