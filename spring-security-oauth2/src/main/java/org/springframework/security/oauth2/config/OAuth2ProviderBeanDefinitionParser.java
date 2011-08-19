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

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationProvider;
import org.springframework.security.oauth2.provider.OAuth2AuthorizationFilter;
import org.springframework.security.oauth2.provider.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.provider.OAuth2ExceptionHandlerFilter;
import org.springframework.security.oauth2.provider.OAuth2ProtectedResourceFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeFilter;
import org.springframework.security.oauth2.provider.code.BasicUserApprovalFilter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.provider.password.ClientPasswordAuthenticationProvider;
import org.springframework.security.oauth2.provider.refresh.RefreshAuthenticationProvider;
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 */
public class OAuth2ProviderBeanDefinitionParser implements BeanDefinitionParser {

  public static String OAUTH2_AUTHENTICATION_MANAGER = "OAuth2" + BeanIds.AUTHENTICATION_MANAGER;

  public BeanDefinition parse(Element element, ParserContext parserContext) {
    List<BeanMetadataElement> filterChain = ConfigUtils.findFilterChain(parserContext, element.getAttribute("filter-chain-ref"));
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
    if (verificationCodeElement != null) {
      parserContext.getReaderContext().error("The 'verification-code' element has been renamed to 'authorization-code'", verificationCodeElement);
    }

    Element authorizationCodeElement = DomUtils.getChildElementByTagName(element, "authorization-code");
    if (authorizationCodeElement == null || !"true".equalsIgnoreCase(authorizationCodeElement.getAttribute("disabled"))) {
      //authorization code grant configuration.
      String approvalPage = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("user-approval-page");
      String approvalParameter = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("approval-parameter-name");
      String authorizationCodeServices = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("services-ref");
      String redirectResolverRef = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("redirect-resolver-ref");
      String authenticationCacheRef = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("authentication-cache-ref");
      String approvalFilterRef = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("user-approval-filter-ref");
      String approvalHandlerRef = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("approval-handler-ref");
      String authorizationCodeRedirectStrategyRef = authorizationCodeElement == null ? null : authorizationCodeElement.getAttribute("redirect-strategy-ref");
      if (!StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
        authorizationCodeRedirectStrategyRef = redirectStrategyRef;
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

      if (!StringUtils.hasText(authorizationCodeServices)) {
        authorizationCodeServices = "oauth2AuthorizationCodeServices";
        BeanDefinitionBuilder authorizationCodeServicesBean = BeanDefinitionBuilder.rootBeanDefinition(InMemoryAuthorizationCodeServices.class);
        parserContext.getRegistry().registerBeanDefinition(authorizationCodeServices, authorizationCodeServicesBean.getBeanDefinition());
      }

      BeanDefinitionBuilder authorizationCodeFilterBean = BeanDefinitionBuilder.rootBeanDefinition(AuthorizationCodeFilter.class);
      if (StringUtils.hasText(clientDetailsRef)) {
        authorizationCodeFilterBean.addPropertyReference("clientDetailsService", clientDetailsRef);
      }
      if (StringUtils.hasText(redirectResolverRef)) {
        authorizationCodeFilterBean.addPropertyReference("redirectResolver", redirectResolverRef);
      }
      if (StringUtils.hasText(authenticationCacheRef)) {
        authorizationCodeFilterBean.addPropertyReference("authenticationCache", authenticationCacheRef);
      }
      if (StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
        authorizationCodeFilterBean.addPropertyReference("redirectStrategy", authorizationCodeRedirectStrategyRef);
      }
      if (StringUtils.hasText(approvalPage)) {
        SimpleUrlAuthenticationFailureHandler approvalPageHandler = new SimpleUrlAuthenticationFailureHandler();
        approvalPageHandler.setDefaultFailureUrl(approvalPage);
        authorizationCodeFilterBean.addPropertyValue("unapprovedAuthenticationHandler", approvalPageHandler);
      }
      if (StringUtils.hasText(userAuthUrl)) {
        authorizationCodeFilterBean.addPropertyValue("filterProcessesUrl", userAuthUrl);
      }
      authorizationCodeFilterBean.addPropertyReference("authorizationCodeServices", authorizationCodeServices);
      authorizationCodeFilterBean.addPropertyReference("userApprovalHandler", approvalHandlerRef);

      BeanDefinitionBuilder authorizationCodeProvider = BeanDefinitionBuilder.rootBeanDefinition(UnconfirmedAuthorizationCodeAuthenticationProvider.class);
      authorizationCodeProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
      authorizationCodeProvider.addPropertyReference("authorizationCodeServices", authorizationCodeServices);

      providers.add(authorizationCodeProvider.getBeanDefinition());

      //add the approval filter to the beginning of the chain so that those who want to combine it with other authentication filters can do so.
      filterChain.add(0, new RuntimeBeanReference(approvalFilterRef));
      filterIndex++;//increment the insert index since we added something at the beginning of the list.

      parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationCodeFilter", authorizationCodeFilterBean.getBeanDefinition());
      filterChain.add(filterIndex++, new RuntimeBeanReference("oauth2AuthorizationCodeFilter"));

      //end authorization code profile configuration.
    }

    //configure the client password mechanism.
    BeanDefinitionBuilder clientPasswordProvider = BeanDefinitionBuilder.rootBeanDefinition(ClientPasswordAuthenticationProvider.class);
    clientPasswordProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
    providers.add(clientPasswordProvider.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientPasswordProvider", clientPasswordProvider.getBeanDefinition());

    // configure the client credentials mechanism
    BeanDefinitionBuilder clientCredentialsProvider = BeanDefinitionBuilder.rootBeanDefinition(ClientCredentialsAuthenticationProvider.class);
    clientCredentialsProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
    providers.add(clientCredentialsProvider.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientCredentialsProvider", clientCredentialsProvider.getBeanDefinition());
    
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
