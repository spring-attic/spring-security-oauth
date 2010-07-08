package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.UnsupportedOAuthFlowTypeException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Basic authorization filter for OAuth 2.0 as defined by http://tools.ietf.org/html/draft-ietf-oauth-v2-05. This authorization filter processes requests from
 * OAuth clients (as opposed to OAuth users via user agent).
 *
 * @author Ryan Heaton
 */
public class OAuth2AuthorizationFilter extends AbstractAuthenticationProcessingFilter {

  private String defaultFlowType = "web_server";
  private OAuth2FlowValve valve = new DefaultOAuth2FlowValve();

  public OAuth2AuthorizationFilter() {
    super("/oauth/authorize");
    setAuthenticationSuccessHandler(new OAuth2AuthorizationSuccessHandler());
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    String flowType = request.getParameter("type");
    if (flowType == null) {
      flowType = getDefaultFlowType();
    }

    Authentication authentication = getValve().setupAuthentication(flowType, request);
    if (authentication == null) {
      throw new UnsupportedOAuthFlowTypeException("Unsupported authorization flow type: " + flowType);
    }

    return getAuthenticationManager().authenticate(authentication);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    SecurityContextHolder.clearContext();
    //just rethrow; let the exception handler mapper take care of it.
    throw failed;
  }

  public String getDefaultFlowType() {
    return defaultFlowType;
  }

  public void setDefaultFlowType(String defaultFlowType) {
    this.defaultFlowType = defaultFlowType;
  }

  public OAuth2FlowValve getValve() {
    return valve;
  }

  public void setValve(OAuth2FlowValve valve) {
    this.valve = valve;
  }

  @Override
  public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
    Assert.isTrue(successHandler instanceof OAuth2AuthorizationSuccessHandler, "OAuth2 authorization filter must be provided with an OAuth2AuthorizationSuccessHandler.");
    super.setAuthenticationSuccessHandler(successHandler);
  }
}
