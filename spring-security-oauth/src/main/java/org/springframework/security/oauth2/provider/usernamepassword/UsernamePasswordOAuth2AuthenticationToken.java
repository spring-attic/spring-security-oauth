package org.springframework.security.oauth2.provider.usernamepassword;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class UsernamePasswordOAuth2AuthenticationToken extends AbstractAuthenticationToken {

  /**
   * The authorization type for the username/password authorization flow.
   */
  public static final String FLOW_TYPE = "username";

  private final ClientAuthenticationToken clientAuthentication;
  private final UsernamePasswordAuthenticationToken userAuthentication;

  /**
   * Whether this token handles the specified authorization type.
   *
   * @param authorizationType The authorization type.
   * @return Whether this token handles the specified authorization type.
   */
  public static boolean handlesType(String authorizationType) {
    return FLOW_TYPE.equals(authorizationType);
  }

  public UsernamePasswordOAuth2AuthenticationToken(HttpServletRequest request) {
    super(null);
    this.clientAuthentication = new ClientAuthenticationToken(request, FLOW_TYPE);
    this.userAuthentication = new UsernamePasswordAuthenticationToken(request.getParameter("username"), request.getParameter("password"));
  }

  public ClientAuthenticationToken getClientAuthentication() {
    return clientAuthentication;
  }

  public UsernamePasswordAuthenticationToken getUserAuthentication() {
    return userAuthentication;
  }

  public Object getPrincipal() {
    return this.userAuthentication.getPrincipal();
  }

  public Object getCredentials() {
    return this.userAuthentication.getCredentials();
  }

  @Override
  public void setDetails(Object details) {
    super.setDetails(details);
    this.clientAuthentication.setDetails(details);
    this.userAuthentication.setDetails(details);
  }
}
