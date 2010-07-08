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

package org.springframework.security.oauth2.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices;
import org.springframework.security.oauth2.provider.usernamepassword.UsernamePasswordOAuth2AuthenticationProvider;
import org.springframework.security.oauth2.provider.webserver.BasicUserApprovalFilter;
import org.springframework.security.oauth2.provider.webserver.InMemoryVerificationCodeServices;
import org.springframework.security.oauth2.provider.webserver.WebServerOAuth2AuthenticationProvider;
import org.springframework.security.oauth2.provider.webserver.WebServerOAuth2Filter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 */
public class OAuth2ProviderBeanDefinitionParser implements BeanDefinitionParser {

  public static String OAUTH2_AUTHENTICATION_MANAGER = "OAuth2" + BeanIds.AUTHENTICATION_MANAGER;

  public BeanDefinition parse(Element element, ParserContext parserContext) {
    BeanDefinition filterChainProxy = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
    Map filterChainMap = (Map) filterChainProxy.getPropertyValues().getPropertyValue("filterChainMap").getValue();
    List<BeanMetadataElement> filterChain = findFilterChain(filterChainMap);

    if (filterChain == null) {
      throw new IllegalStateException("Unable to find the filter chain for the universal pattern matcher where the oauth filters are to be inserted.");
    }

    String clientDetailsRef = element.getAttribute("client-details-service-ref");
    String tokenServicesRef = element.getAttribute("token-services-ref");
    String authUrl = element.getAttribute("authorization-url");
    String defaultFlow = element.getAttribute("default-flow");
    String authSuccessHandlerRef = element.getAttribute("authorization-success-handler-ref");
    String serializerRef = element.getAttribute("serialization-service-ref");
    String valveRef = element.getAttribute("valve-ref");
    String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

    if (!StringUtils.hasText(tokenServicesRef)) {
      tokenServicesRef = "oauth2TokenServices";
      BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(InMemoryOAuth2ProviderTokenServices.class);
      parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
    }

    if (!StringUtils.hasText(authSuccessHandlerRef)) {
      authSuccessHandlerRef = "oauth2AuthorizationSuccessHandler";
      BeanDefinitionBuilder successHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationSuccessHandler.class);
      if (StringUtils.hasText(serializerRef)) {
        successHandler.addPropertyReference("serializationService", serializerRef);
      }
      if (StringUtils.hasText(tokenServicesRef)) {
        successHandler.addPropertyReference("tokenServices", tokenServicesRef);
      }
      parserContext.getRegistry().registerBeanDefinition(authSuccessHandlerRef, successHandler.getBeanDefinition());
    }

    BeanDefinitionBuilder clientAuthProvider = BeanDefinitionBuilder.rootBeanDefinition(ClientAuthenticationProvider.class);
    if (StringUtils.hasText(clientDetailsRef)) {
      clientAuthProvider.addPropertyReference("clientDetailsService", clientDetailsRef);
    }

    List<BeanMetadataElement> providers = new ManagedList<BeanMetadataElement>();
    providers.add(clientAuthProvider.getBeanDefinition());

    BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
    if (StringUtils.hasText(serializerRef)) {
      exceptionHandler.addPropertyReference("serializationService", serializerRef);
    }

    int filterIndex = insertIndex(filterChain);
    parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter", exceptionHandler.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));

    Element webServerElement = null;
    Element usernamePasswordElement = null;
    List flowsElementList = DomUtils.getChildElementsByTagName(element, "flows");
    if (flowsElementList != null && !flowsElementList.isEmpty()) {
      Element flowsElement = (Element) flowsElementList.get(0);

      List webServerElementList = DomUtils.getChildElementsByTagName(flowsElement, "web_server");
      if (webServerElementList != null && !webServerElementList.isEmpty()) {
        webServerElement = (Element) webServerElementList.get(0);
      }

      List usernamePasswordElementList = DomUtils.getChildElementsByTagName(flowsElement, "username");
      if (usernamePasswordElementList != null && !usernamePasswordElementList.isEmpty()) {
        usernamePasswordElement = (Element) usernamePasswordElementList.get(0);
      }

      List userAgentFlowElementList = DomUtils.getChildElementsByTagName(flowsElement, "user_agent");
      if (userAgentFlowElementList != null && !userAgentFlowElementList.isEmpty()) {
        Element userAgentElement = (Element) userAgentFlowElementList.get(0);
        if (!"true".equalsIgnoreCase(userAgentElement.getAttribute("disabled"))) {
          parserContext.getReaderContext().fatal("'user_agent' flow isn't supported yet.", userAgentElement);
        }
      }

      List deviceFlowElementList = DomUtils.getChildElementsByTagName(flowsElement, "device_code");
      if (deviceFlowElementList != null && !deviceFlowElementList.isEmpty()) {
        Element deviceFlowElement = (Element) deviceFlowElementList.get(0);
        if (!"true".equalsIgnoreCase(deviceFlowElement.getAttribute("disabled"))) {
          parserContext.getReaderContext().fatal("'device_code' flow isn't supported yet.", deviceFlowElement);
        }
      }

      List clientCredentialsFlowElementList = DomUtils.getChildElementsByTagName(flowsElement, "client_credentials");
      if (clientCredentialsFlowElementList != null && clientCredentialsFlowElementList.size() > 0) {
        Element clientCredentialsFlowElement = (Element) clientCredentialsFlowElementList.get(0);
        if (!"true".equalsIgnoreCase(clientCredentialsFlowElement.getAttribute("disabled"))) {
          parserContext.getReaderContext().fatal("'client_credentials' flow isn't supported yet.", clientCredentialsFlowElement);
        }
      }

      List assertionFlowElementList = DomUtils.getChildElementsByTagName(flowsElement, "assertion");
      if (assertionFlowElementList != null && !assertionFlowElementList.isEmpty()) {
        Element assertionFlowElement = (Element) assertionFlowElementList.get(0);
        if (!"true".equalsIgnoreCase(assertionFlowElement.getAttribute("disabled"))) {
          parserContext.getReaderContext().fatal("'assertion' flow isn't supported yet.", assertionFlowElement);
        }
      }
    }

    if (webServerElement == null || !"true".equalsIgnoreCase(webServerElement.getAttribute("disabled"))) {
      //web_server flow configuration.
      String approvalPage = webServerElement == null ? null : webServerElement.getAttribute("user-approval-page");
      String approvalParameter = webServerElement == null ? null : webServerElement.getAttribute("approval-parameter-name");
      String verificationServicesRef = webServerElement == null ? null : webServerElement.getAttribute("verification-code-services-ref");
      String redirectResolverRef = webServerElement == null ? null : webServerElement.getAttribute("redirect-resolver-ref");
      String authenticationCacheRef = webServerElement == null ? null : webServerElement.getAttribute("authentication-cache-ref");
      String approvalFilterRef = webServerElement == null ? null : webServerElement.getAttribute("user-approval-filter-ref");
      String approvalHandlerRef = webServerElement == null ? null : webServerElement.getAttribute("approval-handler-ref");

      if (!StringUtils.hasText(approvalFilterRef)) {
        approvalFilterRef = "oauth2ApprovalFilter";
        BeanDefinitionBuilder approvalFilter = BeanDefinitionBuilder.rootBeanDefinition(BasicUserApprovalFilter.class);
        parserContext.getRegistry().registerBeanDefinition(approvalFilterRef, approvalFilter.getBeanDefinition());
        if (!StringUtils.hasText(approvalHandlerRef)) {
          approvalHandlerRef = approvalFilterRef;
        }
      }

      if (!StringUtils.hasText(approvalHandlerRef)) {
        approvalHandlerRef = "oauth2ApprovalHandler";
        BeanDefinitionBuilder approvalHandler = BeanDefinitionBuilder.rootBeanDefinition(BasicUserApprovalFilter.class);
        if (StringUtils.hasText(approvalParameter)) {
          approvalHandler.addPropertyValue("approvalParameter", approvalParameter);
        }
        if (StringUtils.hasText(authenticationCacheRef)) {
          approvalHandler.addPropertyReference("authenticationCache", authenticationCacheRef);
        }
        parserContext.getRegistry().registerBeanDefinition(approvalHandlerRef, approvalHandler.getBeanDefinition());
      }

      if (!StringUtils.hasText(verificationServicesRef)) {
        verificationServicesRef = "oauth2VerificationServices";
        BeanDefinitionBuilder verificationServices = BeanDefinitionBuilder.rootBeanDefinition(InMemoryVerificationCodeServices .class);
        parserContext.getRegistry().registerBeanDefinition(verificationServicesRef, verificationServices.getBeanDefinition());
      }

      BeanDefinitionBuilder webServerFilterBean = BeanDefinitionBuilder.rootBeanDefinition(WebServerOAuth2Filter.class);
      if (StringUtils.hasText(clientDetailsRef)) {
        webServerFilterBean.addPropertyReference("clientDetailsService", clientDetailsRef);
      }
      if (StringUtils.hasText(redirectResolverRef)) {
        webServerFilterBean.addPropertyReference("redirectResolver", redirectResolverRef);
      }
      if (StringUtils.hasText(authenticationCacheRef)) {
        webServerFilterBean.addPropertyReference("authenticationCache", authenticationCacheRef);
      }
      if (StringUtils.hasText(redirectStrategyRef)) {
        webServerFilterBean.addPropertyReference("redirectStrategy", redirectStrategyRef);
      }
      if (StringUtils.hasText(approvalPage)) {
        SimpleUrlAuthenticationFailureHandler approvalPageHandler = new SimpleUrlAuthenticationFailureHandler();
        approvalPageHandler.setDefaultFailureUrl(approvalPage);
        webServerFilterBean.addPropertyValue("unapprovedAuthenticationHandler", approvalPageHandler);
      }
      webServerFilterBean.addPropertyReference("verificationServices", verificationServicesRef);
      webServerFilterBean.addPropertyReference("userApprovalHandler", approvalHandlerRef);

      BeanDefinitionBuilder webServerProvider = BeanDefinitionBuilder.rootBeanDefinition(WebServerOAuth2AuthenticationProvider.class);
      webServerProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
      webServerProvider.addPropertyReference("verificationServices", verificationServicesRef);

      providers.add(webServerProvider.getBeanDefinition());

      //add the approval filter to the beginning of the chain so that those who want to combine it with other authentication filters can do so.
      filterChain.add(0, new RuntimeBeanReference(approvalFilterRef));
      filterIndex++;//increment the insert index since we added something at the beginning of the list.

      parserContext.getRegistry().registerBeanDefinition("oauth2WebServerFlowFilter", webServerFilterBean.getBeanDefinition());
      filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2WebServerFlowFilter"));

      //end web_server flow configuration
    }

    if (usernamePasswordElement == null || !"true".equalsIgnoreCase(usernamePasswordElement.getAttribute("disabled"))) {
      //username_password flow configuration
      BeanDefinitionBuilder usernamePasswordProvider = BeanDefinitionBuilder.rootBeanDefinition(UsernamePasswordOAuth2AuthenticationProvider.class);
      usernamePasswordProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
      providers.add(usernamePasswordProvider.getBeanDefinition());

      parserContext.getRegistry().registerBeanDefinition("oauth2UsernamePasswordProvider", usernamePasswordProvider.getBeanDefinition());
      //end username_password flow configuration
    }

    BeanDefinitionBuilder authFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationFilter.class);
    if (StringUtils.hasText(authUrl)) {
      authFilterBean.addPropertyValue("filterProcessesUrl", authUrl);
    }
    if (StringUtils.hasText(authSuccessHandlerRef)) {
      authFilterBean.addPropertyReference("authenticationSuccessHandler", authSuccessHandlerRef);
    }
    if (StringUtils.hasText(defaultFlow)) {
      authFilterBean.addPropertyValue("defaultFlowType", defaultFlow);
    }
    if (StringUtils.hasText(valveRef)) {
      authFilterBean.addPropertyReference("valve", valveRef);
    }
    authFilterBean.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);

    BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
    if (StringUtils.hasText(tokenServicesRef)) {
      protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }

    parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationFilter", authFilterBean.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2AuthorizationFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauth2ProtectedResourceFilter", protectedResourceFilterBean.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2ProtectedResourceFilter"));

    //instantiate the oauth provider manager...
    BeanDefinitionBuilder oauthProviderManagerBean = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
    oauthProviderManagerBean.addPropertyReference("parent", BeanIds.AUTHENTICATION_MANAGER);
    oauthProviderManagerBean.addPropertyValue("providers", providers);

    parserContext.getRegistry().registerBeanDefinition(OAUTH2_AUTHENTICATION_MANAGER, oauthProviderManagerBean.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientProvider", clientAuthProvider.getBeanDefinition());

    return null;
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

  /**
   * Attempts to find the place in the filter chain to insert the spring security oauth filters. Currently,
   * these filters are inserted after the ExceptionTranslationFilter.
   *
   * @param filterChain The filter chain configuration.
   * @return The insert index.
   */
  private int insertIndex(List<BeanMetadataElement> filterChain) {
    int i;
    for (i = 0; i < filterChain.size(); i++) {
      BeanMetadataElement filter = filterChain.get(i);
      if (filter instanceof BeanDefinition) {
        String beanName = ((BeanDefinition) filter).getBeanClassName();
        if (beanName.equals(ExceptionTranslationFilter.class.getName())) {
           return i + 1;
        }
      }
    }
    return filterChain.size();
  }
}