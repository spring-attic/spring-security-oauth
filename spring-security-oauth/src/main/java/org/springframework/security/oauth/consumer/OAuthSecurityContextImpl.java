package org.springframework.security.oauth.consumer;


import java.util.Map;

/**
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
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
