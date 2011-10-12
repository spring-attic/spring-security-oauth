package org.springframework.security.oauth2.config;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.security.oauth2.client.resource.InMemoryOAuth2ProtectedResourceDetailsService;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetailsService;

import java.util.Map;

/**
 * Factory bean for the resource details service.
 *
 * @author Ryan Heaton
 */
public class ResourceDetailsServiceFactoryBean extends AbstractFactoryBean<OAuth2ProtectedResourceDetailsService>  {

  @Override
  public Class<? extends OAuth2ProtectedResourceDetailsService> getObjectType() {
    return OAuth2ProtectedResourceDetailsService.class;
  }

  @Override
  protected OAuth2ProtectedResourceDetailsService createInstance() throws Exception {
    Map<String,OAuth2ProtectedResourceDetails> detailsMap = BeanFactoryUtils.beansOfTypeIncludingAncestors((ListableBeanFactory) getBeanFactory(),
                                                                                                           OAuth2ProtectedResourceDetails.class);
    InMemoryOAuth2ProtectedResourceDetailsService service = new InMemoryOAuth2ProtectedResourceDetailsService();
    service.setResourceDetailsStore(detailsMap);
    return service;
  }
}
