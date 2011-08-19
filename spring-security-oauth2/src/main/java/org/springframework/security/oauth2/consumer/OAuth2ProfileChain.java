package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.webserver.WebServerProfile;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A chain of OAuth2 profiles. This implementation will iterate through its chain to find the first profile that supports the resource
 * and use it to obtain the access token. Note, then, that the order of the chain is relevant.
 *
 * @author Ryan Heaton
 */
public class OAuth2ProfileChain extends AbstractOAuth2ProfileManager {

  private final List<OAuth2Profile> chain;

  public OAuth2ProfileChain() {
    this(Arrays.asList((OAuth2Profile) new WebServerProfile()));
  }

  public OAuth2ProfileChain(List<OAuth2Profile> chain) {
    this.chain = chain == null ? Collections.<OAuth2Profile>emptyList() : Collections.unmodifiableList(chain);
  }

  @Override
  protected OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    for (OAuth2Profile profile : chain) {
      if (profile.supportsResource(details)) {
        return profile.obtainNewAccessToken(details);
      }
    }

    throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId() + "'. The profile manager is not configured to support it.", details);
  }

  /**
   * The chain.
   *
   * @return The chain.
   */
  public List<OAuth2Profile> getChain() {
    return chain;
  }

}
