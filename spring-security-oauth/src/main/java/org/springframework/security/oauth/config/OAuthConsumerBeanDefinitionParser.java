/*
 * Copyright 2008-2009 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth.consumer.client.CoreOAuthConsumerSupport;
import org.springframework.security.oauth.consumer.filter.OAuthConsumerContextFilter;
import org.springframework.security.oauth.consumer.filter.OAuthConsumerProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Parser for the OAuth "consumer" element.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 * @author Luke Taylor
 */
public class OAuthConsumerBeanDefinitionParser implements BeanDefinitionParser {

  public BeanDefinition parse(Element element, ParserContext parserContext) {
    BeanDefinitionBuilder consumerContextFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuthConsumerContextFilter.class);

    String failureHandlerRef = element.getAttribute("failure-handler-ref");
    if (StringUtils.hasText(failureHandlerRef)) {
      consumerContextFilterBean.addPropertyReference("OAuthFailureHandler", failureHandlerRef);
    }
    else {
      String failurePage = element.getAttribute("oauth-failure-page");
      if (StringUtils.hasText(failurePage)) {
        AccessDeniedHandlerImpl failureHandler = new AccessDeniedHandlerImpl();
        failureHandler.setErrorPage(failurePage);
        consumerContextFilterBean.addPropertyValue("OAuthFailureHandler", failureHandler);
      }
    }

    String resourceDetailsRef = element.getAttribute("resource-details-service-ref");
    String supportRef = element.getAttribute("support-ref");
    if (!StringUtils.hasText(supportRef)) {
      BeanDefinitionBuilder consumerSupportBean = BeanDefinitionBuilder.rootBeanDefinition(CoreOAuthConsumerSupport.class);

      if (StringUtils.hasText(resourceDetailsRef)) {
        consumerSupportBean.addPropertyReference("protectedResourceDetailsService", resourceDetailsRef);
      }
      parserContext.getRegistry().registerBeanDefinition("oauthConsumerSupport", consumerSupportBean.getBeanDefinition());
      supportRef = "oauthConsumerSupport";
    }
    consumerContextFilterBean.addPropertyReference("consumerSupport", supportRef);

    String tokenServicesFactoryRef = element.getAttribute("token-services-ref");
    if (StringUtils.hasText(tokenServicesFactoryRef)) {
      consumerContextFilterBean.addPropertyReference("tokenServices", tokenServicesFactoryRef);
    }

    String rememberMeServicesRef = element.getAttribute("remember-me-services-ref");
    if (StringUtils.hasText(rememberMeServicesRef)) {
      consumerContextFilterBean.addPropertyReference("rememberMeServices", rememberMeServicesRef);
    }

    String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");
    if (StringUtils.hasText(redirectStrategyRef)) {
      consumerContextFilterBean.addPropertyReference("redirectStrategy", redirectStrategyRef);
    }

    parserContext.getRegistry().registerBeanDefinition("oauthConsumerContextFilter", consumerContextFilterBean.getBeanDefinition());
    List<BeanMetadataElement> filterChain = ConfigUtils.findFilterChain(parserContext, element.getAttribute("filter-chain-ref"));
    filterChain.add(filterChain.size(), new RuntimeBeanReference("oauthConsumerContextFilter"));

    BeanDefinition fids = ConfigUtils.createSecurityMetadataSource(element, parserContext);
    if (fids != null) {
      BeanDefinitionBuilder consumerAccessFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuthConsumerProcessingFilter.class);

      if (StringUtils.hasText(resourceDetailsRef)) {
        consumerAccessFilterBean.addPropertyReference("protectedResourceDetailsService", resourceDetailsRef);
      }

      String requireAuthenticated = element.getAttribute("requireAuthenticated");
      if (StringUtils.hasText(requireAuthenticated)) {
        consumerAccessFilterBean.addPropertyValue("requireAuthenticated", requireAuthenticated);
      }

      consumerAccessFilterBean.addPropertyValue("objectDefinitionSource", fids);
      parserContext.getRegistry().registerBeanDefinition("oauthConsumerFilter", consumerAccessFilterBean.getBeanDefinition());
      filterChain.add(filterChain.size(), new RuntimeBeanReference("oauthConsumerFilter"));
    }

    return null;
  }

}
