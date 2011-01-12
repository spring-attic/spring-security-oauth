package org.springframework.security.oauth2.provider;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Basic authorization filter for OAuth 2.0 as defined by http://tools.ietf.org/html/draft-ietf-oauth-v2. This authorization filter processes requests from
 * OAuth clients (as opposed to OAuth users via user agent) and delivers access tokens.
 *
 * @author Ryan Heaton
 */
public class OAuth2AuthorizationFilter extends AbstractAuthenticationProcessingFilter {

  private String defaultGrantType = "authorization_code";
  private OAuth2GrantManager grantManager = new DefaultOAuth2GrantManager();

  public OAuth2AuthorizationFilter() {
    super("/oauth/authorize");
    setAuthenticationSuccessHandler(new OAuth2AuthorizationSuccessHandler());
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    String grantType = request.getParameter("grant_type");
    if (grantType == null) {
      grantType = getDefaultGrantType();
    }

    Authentication authentication = getGrantManager().setupAuthentication(grantType, request);
    if (authentication == null) {
      throw new UnsupportedGrantTypeException("Unsupported grant type: " + grantType);
    }

    return getAuthenticationManager().authenticate(authentication);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    SecurityContextHolder.clearContext();
    //just rethrow; let the exception handler mapper take care of it.
    throw failed;
  }

  public String getDefaultGrantType() {
    return defaultGrantType;
  }

  public void setDefaultGrantType(String defaultGrantType) {
    this.defaultGrantType = defaultGrantType;
  }

  public OAuth2GrantManager getGrantManager() {
    return grantManager;
  }

  public void setGrantManager(OAuth2GrantManager grantManager) {
    this.grantManager = grantManager;
  }

  @Override
  public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
    Assert.isTrue(successHandler instanceof OAuth2AuthorizationSuccessHandler, "OAuth2 authorization filter must be provided with an OAuth2AuthorizationSuccessHandler.");
    super.setAuthenticationSuccessHandler(successHandler);
  }
}
