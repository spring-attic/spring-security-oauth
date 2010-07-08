package org.springframework.security.oauth2.provider;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.usernamepassword.UsernamePasswordOAuth2AuthenticationToken;
import org.springframework.security.oauth2.provider.webserver.WebServerOAuth2AuthenticationToken;

import javax.servlet.http.HttpServletRequest;

/**
 * Default implementation of the OAuth 2 flow valve.
 *
 * @author Ryan Heaton
 */
public class DefaultOAuth2FlowValve implements OAuth2FlowValve {

  public Authentication setupAuthentication(String flowType, HttpServletRequest request) {
    if (UsernamePasswordOAuth2AuthenticationToken.handlesType(flowType)) {
      return new UsernamePasswordOAuth2AuthenticationToken(request);
    }

    if (WebServerOAuth2AuthenticationToken.handlesType(flowType)) {
      return new WebServerOAuth2AuthenticationToken(request);
    }

    return null;
  }

}
