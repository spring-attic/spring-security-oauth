package org.springframework.security.oauth.provider.token;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.BeansException;

import java.util.Map;

/**
 * Bean post-processor that ensures all lifecycle listener beans are registered with all lifecycle registries.
 *
 * @author Ryan Heaton
 */
public class OAuthTokenLifecycleRegistryPostProcessor implements BeanFactoryPostProcessor {

  public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
    Map<String, OAuthTokenLifecycleRegistry> registryBeans = BeanFactoryUtils.beansOfTypeIncludingAncestors(beanFactory, OAuthTokenLifecycleRegistry.class);
    Map<String, OAuthTokenLifecycleListener> listenerBeans = BeanFactoryUtils.beansOfTypeIncludingAncestors(beanFactory, OAuthTokenLifecycleListener.class);
    for (OAuthTokenLifecycleRegistry registry : registryBeans.values()) {
      for (OAuthTokenLifecycleListener listener : listenerBeans.values()) {
        registry.register(listener);
      }
    }
  }
}
