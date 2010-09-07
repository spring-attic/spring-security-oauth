package org.springframework.security.oauth2.consumer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * @author Ryan Heaton
 */
public abstract class AbstractOAuth2Flow implements OAuth2Flow, InitializingBean {

  private RestTemplate restTemplate = new RestTemplate();
  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(restTemplate, "A RestTemplate is required.");
    Assert.notNull(serializationService, "OAuth2 serialization service is required.");
  }

  public RestTemplate getRestTemplate() {
    return restTemplate;
  }

  public void setRestTemplate(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }
}
