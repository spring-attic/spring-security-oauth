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
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.http.MatcherType;
import org.springframework.security.oauth.consumer.CoreOAuthConsumerSupport;
import org.springframework.security.oauth.consumer.OAuthConsumerContextFilter;
import org.springframework.security.oauth.consumer.OAuthConsumerProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

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

    parserContext.getRegistry().registerBeanDefinition("oauthConsumerContextFilter", consumerContextFilterBean.getBeanDefinition());
    BeanDefinition filterChainProxy = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
    Map filterChainMap = (Map) filterChainProxy.getPropertyValues().getPropertyValue("filterChainMap").getValue();
    List<BeanMetadataElement> filterChain = findFilterChain(filterChainMap);
    filterChain.add(filterChain.size(), new RuntimeBeanReference("oauthConsumerContextFilter"));


    BeanDefinition fids = createSecurityMetadataSource(element, parserContext);
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

  public static BeanDefinition createSecurityMetadataSource(Element element, ParserContext pc) {
    List<Element> filterPatterns = DomUtils.getChildElementsByTagName(element, "url");

    if (filterPatterns.isEmpty()) {
      return null;
    }

    String patternType = element.getAttribute("path-type");
    if (!StringUtils.hasText(patternType)) {
      patternType = "ant";
    }

    MatcherType matcherType = MatcherType.valueOf(patternType);

    ManagedMap<BeanDefinition, BeanDefinition> invocationDefinitionMap = new ManagedMap<BeanDefinition, BeanDefinition>();

    for (Element filterPattern : filterPatterns) {
      String path = filterPattern.getAttribute("pattern");
      if (!StringUtils.hasText(path)) {
        pc.getReaderContext().error("pattern attribute cannot be empty or null", filterPattern);
      }

      String method = filterPattern.getAttribute("httpMethod");
      if (!StringUtils.hasText(method)) {
        method = null;
      }

      String access = filterPattern.getAttribute("resources");

      if (StringUtils.hasText(access)) {
        BeanDefinition matcher = matcherType.createMatcher(path, method);
        BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
        attributeBuilder.addConstructorArgValue(access);
        attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");

        if (invocationDefinitionMap.containsKey(matcher)) {
            pc.getReaderContext().warning("Duplicate URL defined: " + path
                + ". The original attribute values will be overwritten", pc.extractSource(filterPattern));
        }

        invocationDefinitionMap.put(matcher, attributeBuilder.getBeanDefinition());
      }
    }

    BeanDefinitionBuilder fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
    fidsBuilder.addConstructorArgValue(invocationDefinitionMap);
    fidsBuilder.getRawBeanDefinition().setSource(pc.extractSource(element));

    return fidsBuilder.getBeanDefinition();
  }

  protected List<BeanMetadataElement> findFilterChain(Map filterChainMap) {
    //the filter chain we want is the last one in the sorted map.
    Iterator valuesIt = filterChainMap.values().iterator();
    while (valuesIt.hasNext()) {
      List<BeanMetadataElement> filterChain = (List<BeanMetadataElement>) valuesIt.next();
      if (!valuesIt.hasNext()) {
        return filterChain;
      }
    }

    return null;
  }

}
