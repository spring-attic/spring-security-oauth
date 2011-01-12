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
import org.springframework.security.oauth2.provider.password.ClientPasswordAuthenticationProvider;
import org.springframework.security.oauth2.provider.refresh.RefreshAuthenticationProvider;
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices;
import org.springframework.security.oauth2.provider.verification.BasicUserApprovalFilter;
import org.springframework.security.oauth2.provider.verification.InMemoryVerificationCodeServices;
import org.springframework.security.oauth2.provider.verification.VerificationCodeFilter;
import org.springframework.security.oauth2.provider.verification.VerificationCodeAuthenticationProvider;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

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
    String userAuthUrl = element.getAttribute("user-authorization-url");
    String defaultGrantType = element.getAttribute("default-grant-type");
    String authSuccessHandlerRef = element.getAttribute("authorization-success-handler-ref");
    String serializerRef = element.getAttribute("serialization-service-ref");
    String grantManagerRef = element.getAttribute("grant-manager-ref");
    String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

    if (!StringUtils.hasText(tokenServicesRef)) {
      tokenServicesRef = "oauth2TokenServices";
      BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(InMemoryOAuth2ProviderTokenServices.class);
      parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
    }

    if (!StringUtils.hasText(authSuccessHandlerRef)) {
      authSuccessHandlerRef = "oauth2AuthorizationSuccessHandler";
      BeanDefinitionBuilder successHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationSuccessHandler.class);
      successHandler.addPropertyReference("tokenServices", tokenServicesRef);
      if (StringUtils.hasText(serializerRef)) {
        successHandler.addPropertyReference("serializationService", serializerRef);
      }
      parserContext.getRegistry().registerBeanDefinition(authSuccessHandlerRef, successHandler.getBeanDefinition());
    }

    BeanDefinitionBuilder clientAuthProvider = BeanDefinitionBuilder.rootBeanDefinition(AccessGrantAuthenticationProvider.class);
    if (StringUtils.hasText(clientDetailsRef)) {
      clientAuthProvider.addPropertyReference("clientDetailsService", clientDetailsRef);
    }
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientProvider", clientAuthProvider.getBeanDefinition());

    List<BeanMetadataElement> providers = new ManagedList<BeanMetadataElement>();
    providers.add(clientAuthProvider.getBeanDefinition());

    BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
    if (StringUtils.hasText(serializerRef)) {
      exceptionHandler.addPropertyReference("serializationService", serializerRef);
    }

    int filterIndex = insertIndex(filterChain);
    parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter", exceptionHandler.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));

    Element verificationCodeElement = DomUtils.getChildElementByTagName(element, "verification-code");
    if (verificationCodeElement == null || !"true".equalsIgnoreCase(verificationCodeElement.getAttribute("disabled"))) {
      //web_server flow configuration.
      String approvalPage = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("user-approval-page");
      String approvalParameter = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("approval-parameter-name");
      String verificationServicesRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("services-ref");
      String redirectResolverRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("redirect-resolver-ref");
      String authenticationCacheRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("authentication-cache-ref");
      String approvalFilterRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("user-approval-filter-ref");
      String approvalHandlerRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("approval-handler-ref");
      String verificationCodeRedirectStrategyRef = verificationCodeElement == null ? null : verificationCodeElement.getAttribute("approval-handler-ref");
      if (!StringUtils.hasText(verificationCodeRedirectStrategyRef)) {
        verificationCodeRedirectStrategyRef = redirectStrategyRef;
      }

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

      BeanDefinitionBuilder verificationCodeFilterBean = BeanDefinitionBuilder.rootBeanDefinition(VerificationCodeFilter.class);
      if (StringUtils.hasText(clientDetailsRef)) {
        verificationCodeFilterBean.addPropertyReference("clientDetailsService", clientDetailsRef);
      }
      if (StringUtils.hasText(redirectResolverRef)) {
        verificationCodeFilterBean.addPropertyReference("redirectResolver", redirectResolverRef);
      }
      if (StringUtils.hasText(authenticationCacheRef)) {
        verificationCodeFilterBean.addPropertyReference("authenticationCache", authenticationCacheRef);
      }
      if (StringUtils.hasText(verificationCodeRedirectStrategyRef)) {
        verificationCodeFilterBean.addPropertyReference("redirectStrategy", verificationCodeRedirectStrategyRef);
      }
      if (StringUtils.hasText(approvalPage)) {
        SimpleUrlAuthenticationFailureHandler approvalPageHandler = new SimpleUrlAuthenticationFailureHandler();
        approvalPageHandler.setDefaultFailureUrl(approvalPage);
        verificationCodeFilterBean.addPropertyValue("unapprovedAuthenticationHandler", approvalPageHandler);
      }
      if (StringUtils.hasText(authUrl)) {
        verificationCodeFilterBean.addPropertyValue("filterProcessesUrl", userAuthUrl);
      }
      verificationCodeFilterBean.addPropertyReference("verificationServices", verificationServicesRef);
      verificationCodeFilterBean.addPropertyReference("userApprovalHandler", approvalHandlerRef);

      BeanDefinitionBuilder verificationCodeProvider = BeanDefinitionBuilder.rootBeanDefinition(VerificationCodeAuthenticationProvider.class);
      verificationCodeProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
      verificationCodeProvider.addPropertyReference("verificationServices", verificationServicesRef);

      providers.add(verificationCodeProvider.getBeanDefinition());

      //add the approval filter to the beginning of the chain so that those who want to combine it with other authentication filters can do so.
      filterChain.add(0, new RuntimeBeanReference(approvalFilterRef));
      filterIndex++;//increment the insert index since we added something at the beginning of the list.

      parserContext.getRegistry().registerBeanDefinition("oauth2VerificationCodeFilter", verificationCodeFilterBean.getBeanDefinition());
      filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2VerificationCodeFilter"));

      //end verification code flow configuration
    }

    //configure the client password mechanism.
    BeanDefinitionBuilder clientPasswordProvider = BeanDefinitionBuilder.rootBeanDefinition(ClientPasswordAuthenticationProvider.class);
    clientPasswordProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
    providers.add(clientPasswordProvider.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientPasswordProvider", clientPasswordProvider.getBeanDefinition());

    //configure the refresh token mechanism.
    BeanDefinitionBuilder refreshTokenProvider = BeanDefinitionBuilder.rootBeanDefinition(RefreshAuthenticationProvider.class);
    refreshTokenProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
    providers.add(refreshTokenProvider.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2RefreshProvider", refreshTokenProvider.getBeanDefinition());

    //configure the authorization filter
    BeanDefinitionBuilder authFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationFilter.class);
    if (StringUtils.hasText(authUrl)) {
      authFilterBean.addPropertyValue("filterProcessesUrl", authUrl);
    }
    if (StringUtils.hasText(authSuccessHandlerRef)) {
      authFilterBean.addPropertyReference("authenticationSuccessHandler", authSuccessHandlerRef);
    }
    if (StringUtils.hasText(defaultGrantType)) {
      authFilterBean.addPropertyValue("defaultGrantType", defaultGrantType);
    }
    if (StringUtils.hasText(grantManagerRef)) {
      authFilterBean.addPropertyReference("grantManager", grantManagerRef);
    }
    authFilterBean.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
    parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationFilter", authFilterBean.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2AuthorizationFilter"));

    //configure the protected resource filter
    BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
    protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    parserContext.getRegistry().registerBeanDefinition("oauth2ProtectedResourceFilter", protectedResourceFilterBean.getBeanDefinition());
    filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2ProtectedResourceFilter"));

    //instantiate the oauth provider manager...
    BeanDefinitionBuilder oauthProviderManagerBean = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
    oauthProviderManagerBean.addPropertyReference("parent", BeanIds.AUTHENTICATION_MANAGER);
    oauthProviderManagerBean.addPropertyValue("providers", providers);
    parserContext.getRegistry().registerBeanDefinition(OAUTH2_AUTHENTICATION_MANAGER, oauthProviderManagerBean.getBeanDefinition());

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
