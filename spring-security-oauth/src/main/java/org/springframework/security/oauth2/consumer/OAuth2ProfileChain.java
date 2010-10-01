package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.webserver.WebServerProfile;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A chain of OAuth2 flows. This implementation will iterate through its chain to find the first flow that supports the resource
 * and use it to obtain the access token. Note, then, that the order of the chain is relevant.
 *
 * @author Ryan Heaton
 */
public class OAuth2ProfileChain extends AbstractOAuth2ProfileManager {

  private final List<AbstractOAuth2Profile> chain;

  public OAuth2ProfileChain() {
    this(Arrays.asList((AbstractOAuth2Profile) new WebServerProfile()));
  }

  public OAuth2ProfileChain(List<AbstractOAuth2Profile> chain) {
    this.chain = chain == null ? Collections.<AbstractOAuth2Profile>emptyList() : Collections.unmodifiableList(chain);
  }

  @Override
  protected OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    for (AbstractOAuth2Profile flow : chain) {
      if (flow.supportsResource(details)) {
        return flow.obtainNewAccessToken(details);
      }
    }

    throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId() + "'. The profile manager is not configured to support it.", details);
  }

  /**
   * The chain.
   *
   * @return The chain.
   */
  public List<AbstractOAuth2Profile> getChain() {
    return chain;
  }

}
