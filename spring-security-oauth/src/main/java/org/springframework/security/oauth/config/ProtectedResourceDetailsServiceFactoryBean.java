package org.springframework.security.oauth.config;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.security.oauth.consumer.InMemoryProtectedResourceDetailsService;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.ProtectedResourceDetailsService;

import java.util.Map;

/**
 * Factory bean for the resource details service.
 *
 * @author Ryan Heaton
 */
public class ProtectedResourceDetailsServiceFactoryBean extends AbstractFactoryBean<ProtectedResourceDetailsService>  {

  @Override
  public Class<? extends ProtectedResourceDetailsService> getObjectType() {
    return InMemoryProtectedResourceDetailsService.class;
  }

  @Override
  protected ProtectedResourceDetailsService createInstance() throws Exception {
    Map<String, ProtectedResourceDetails> detailsMap = BeanFactoryUtils.beansOfTypeIncludingAncestors((ListableBeanFactory) getBeanFactory(),
                                                                                                           ProtectedResourceDetails.class);
    InMemoryProtectedResourceDetailsService service = new InMemoryProtectedResourceDetailsService();
    service.setResourceDetailsStore(detailsMap);
    return service;
  }
}
