package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class WebServerOAuth2AuthenticationToken extends AbstractAuthenticationToken {

  /**
   * The authorization type for the web server authorization flow.
   */
  public static final String FLOW_TYPE = "web_server";

  private final ClientAuthenticationToken clientAuthentication;

  /**
   * Whether this token handles the specified authorization type.
   *
   * @param authorizationType The authorization type.
   * @return Whether this token handles the specified authorization type.
   */
  public static boolean handlesType(String authorizationType) {
    //facebook handles "web-server" but the spec says "web_server". we'll just handle both for now.
    return FLOW_TYPE.equals(authorizationType) || "web-server".equals(authorizationType);
  }

  public WebServerOAuth2AuthenticationToken(HttpServletRequest request) {
    super(null);
    this.clientAuthentication = new ClientAuthenticationToken(request, FLOW_TYPE);
  }

  public ClientAuthenticationToken getClientAuthentication() {
    return clientAuthentication;
  }

  public Object getPrincipal() {
    return this.clientAuthentication.getPrincipal();
  }

  public Object getCredentials() {
    return this.clientAuthentication.getCredentials();
  }

  @Override
  public void setDetails(Object details) {
    super.setDetails(details);
    this.clientAuthentication.setDetails(details);
  }
}