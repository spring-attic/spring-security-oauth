package org.springframework.security.oauth.consumer.client;

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.web.client.RestTemplate;

/**
 * Rest template that is able to make OAuth-authenticated REST requests with the credentials of the provided resource.
 *
 * @author Ryan Heaton
 */
public class OAuthRestTemplate extends RestTemplate {

  private final ProtectedResourceDetails resource;
  private OAuthConsumerSupport support = new CoreOAuthConsumerSupport();

  public OAuthRestTemplate(ProtectedResourceDetails resource) {
    this(new SimpleClientHttpRequestFactory(), resource);
  }

  public OAuthRestTemplate(ClientHttpRequestFactory requestFactory, ProtectedResourceDetails resource) {
    super();
    if (resource == null) {
      throw new IllegalArgumentException("An OAuth resource must be supplied.");
    }
    if (support == null) {
      throw new IllegalArgumentException("OAuth support must be supplied.");
    }

    this.resource = resource;
    setRequestFactory(requestFactory);
  }

  @Override
  public void setRequestFactory(ClientHttpRequestFactory requestFactory) {
    if (!(requestFactory instanceof OAuthClientHttpRequestFactory)) {
      requestFactory = new OAuthClientHttpRequestFactory(requestFactory, getResource(), getSupport());
    }
    super.setRequestFactory(requestFactory);
  }


  public ProtectedResourceDetails getResource() {
    return resource;
  }

  /**
   * The support logic to use.
   *
   * @return The support logic to use.
   */
  public OAuthConsumerSupport getSupport() {
    return support;
  }

  /**
   * The support logic to use.
   *
   * @param support The support logic to use.
   */
  public void setSupport(OAuthConsumerSupport support) {
    this.support = support;
  }

}
