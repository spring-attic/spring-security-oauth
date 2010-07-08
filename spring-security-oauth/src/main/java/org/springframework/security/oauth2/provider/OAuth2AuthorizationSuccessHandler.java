package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.token.OAuth2ProviderTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler for a successful OAuth 2 authorization call.
 * 
 * @author Ryan Heaton
 */
public class OAuth2AuthorizationSuccessHandler implements AuthenticationSuccessHandler, InitializingBean {

  private OAuth2ProviderTokenServices tokenServices;
  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(getTokenServices(), "OAuth 2 token services must be supplied.");
  }

  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if (authentication instanceof OAuth2Authentication) {
      if (!authentication.isAuthenticated()) {
        throw new OAuth2Exception("Not authenticated.");
      }

      OAuth2AccessToken accessToken = getTokenServices().createAccessToken((OAuth2Authentication) authentication);
      OAuth2Serialization serialization = getSerializationService().serialize(accessToken, request.getParameter("form"));
      response.setHeader("Cache-Control","no-store");
      response.setContentType(serialization.getMediaType());
      response.getWriter().write(serialization.getSerializedForm());
      return;
    }

    throw new OAuth2Exception("Unsupported authentication for OAuth 2: " + authentication);
  }

  public OAuth2ProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  @Autowired
  public void setTokenServices(OAuth2ProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  @Autowired
  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }
}
