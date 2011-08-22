package org.springframework.security.oauth.consumer;


import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class OAuthSecurityContextImpl implements OAuthSecurityContext {

  private Map<String, OAuthConsumerToken> accessTokens;
  private Object details;

  public Map<String, OAuthConsumerToken> getAccessTokens() {
    return accessTokens;
  }

  public void setAccessTokens(Map<String, OAuthConsumerToken> accessTokens) {
    this.accessTokens = accessTokens;
  }

  public Object getDetails() {
    return details;
  }

  public void setDetails(Object details) {
    this.details = details;
  }
}
