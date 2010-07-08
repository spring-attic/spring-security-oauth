package org.springframework.security.oauth2.common.exceptions;

import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class UserDeniedAuthenticationException extends OAuth2Exception {

  private ClientAuthenticationToken clientAuthentication;

  public UserDeniedAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }

  public UserDeniedAuthenticationException(String msg) {
    super(msg);
  }

  public UserDeniedAuthenticationException(String msg, Object extraInformation) {
    super(msg, extraInformation);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "user_denied";
  }

  public ClientAuthenticationToken getClientAuthentication() {
    return clientAuthentication;
  }

  public void setClientAuthentication(ClientAuthenticationToken clientAuthentication) {
    this.clientAuthentication = clientAuthentication;
  }

  @Override
  public Map<String, String> getAdditionalInformation() {
    Map<String, String> additionalInfo = super.getAdditionalInformation();
    if (getClientAuthentication() != null) {
      if (getClientAuthentication().getState() != null) {
        if (additionalInfo == null) {
          additionalInfo = new HashMap<String, String>();
        }

        additionalInfo.put("state", getClientAuthentication().getState());
      }
    }
    return additionalInfo;
  }
}
