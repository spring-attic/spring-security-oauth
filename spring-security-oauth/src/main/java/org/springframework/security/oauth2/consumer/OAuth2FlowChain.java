package org.springframework.security.oauth2.consumer;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.webserver.WebServerFlow;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A chain of OAuth2 flows. This implementation will iterate through its chain to find the first flow that supports the resource
 * and use it to obtain the access token. Note, then that the order of the chain is relevant.
 *
 * @author Ryan Heaton
 */
public class OAuth2FlowChain extends AbstractOAuth2FlowManager {

  private final List<AbstractOAuth2Flow> chain;

  public OAuth2FlowChain() {
    this(Arrays.asList((AbstractOAuth2Flow) new WebServerFlow()));
  }

  public OAuth2FlowChain(List<AbstractOAuth2Flow> chain) {
    this.chain = chain == null ? Collections.<AbstractOAuth2Flow>emptyList() : Collections.unmodifiableList(chain);
  }

  @Override
  protected OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    for (AbstractOAuth2Flow flow : chain) {
      if (flow.supportsResource(details)) {
        return flow.obtainNewAccessToken(details);
      }
    }

    throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId() + "'. The flow manager is not configured to support it.", details);
  }

  /**
   * The chain.
   *
   * @return The chain.
   */
  public List<AbstractOAuth2Flow> getChain() {
    return chain;
  }

}
