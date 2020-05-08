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
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
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
