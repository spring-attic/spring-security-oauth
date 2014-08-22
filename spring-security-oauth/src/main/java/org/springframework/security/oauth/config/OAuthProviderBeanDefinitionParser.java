/*
 * Copyright 2008-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.springframework.security.oauth.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.TypedStringValue;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth.common.OAuthConstants;
import org.springframework.security.oauth.provider.endpoint.AccessTokenEndpoint;
import org.springframework.security.oauth.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth.provider.endpoint.RequestTokenEndpoint;
import org.springframework.security.oauth.provider.filter.OAuthProviderProcessingFilter;
import org.springframework.security.oauth.provider.endpoint.UserAuthorizationSuccessfulAuthenticationHandler;
import org.springframework.security.oauth.provider.verifier.RandomValueVerifierServices;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class OAuthProviderBeanDefinitionParser implements BeanDefinitionParser {

	public BeanDefinition parse(Element element, ParserContext parserContext) {
		String consumerDetailsRef = element.getAttribute("consumer-details-service-ref");
		String tokenServicesRef = element.getAttribute("token-services-ref");

		BeanDefinitionBuilder requestTokenEndpoint = BeanDefinitionBuilder.rootBeanDefinition(RequestTokenEndpoint.class);
		if (StringUtils.hasText(tokenServicesRef)) {
			requestTokenEndpoint.addPropertyReference("tokenServices", tokenServicesRef);
		}
		String requestTokenURL = element.getAttribute("request-token-url");

		BeanDefinitionBuilder authorizationEndpoint = BeanDefinitionBuilder.rootBeanDefinition(AuthorizationEndpoint.class);
		if (StringUtils.hasText(tokenServicesRef)) {
			authorizationEndpoint.addPropertyReference("tokenServices", tokenServicesRef);
		}
		String authenticateTokenURL = element.getAttribute("authenticate-token-url");

		String accessGrantedURL = element.getAttribute("access-granted-url");
		if (!StringUtils.hasText(accessGrantedURL)) {
			// create the simple URl handler and add it.
			accessGrantedURL = "/";
		}

		// create a AuthenticationSuccessHandler
		BeanDefinitionBuilder successfulAuthenticationHandler = BeanDefinitionBuilder.rootBeanDefinition(UserAuthorizationSuccessfulAuthenticationHandler.class);
		successfulAuthenticationHandler.addConstructorArgValue(accessGrantedURL);

		String callbackUrlParam = element.getAttribute("callback-url-param");
		if (StringUtils.hasText(callbackUrlParam)) {
			successfulAuthenticationHandler.addPropertyValue("callbackParameterName", callbackUrlParam);
		}

		// create a AuthenticationFailureHandler
		BeanDefinitionBuilder simpleUrlAuthenticationFailureHandler = BeanDefinitionBuilder.rootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
		String authenticationFailedURL = element.getAttribute("authentication-failed-url");
		if (StringUtils.hasText(authenticationFailedURL)) {
			simpleUrlAuthenticationFailureHandler.addConstructorArgValue(authenticationFailedURL);
		}

		// create a AuthenticationFailureHandler
		BeanDefinitionBuilder failedAuthenticationHandler = BeanDefinitionBuilder.rootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
		String userApprovalUrl = element.getAttribute("user-approval-url");
		if (StringUtils.hasText(userApprovalUrl)) {
			failedAuthenticationHandler.addConstructorArgValue(userApprovalUrl);
		}
		else {
			failedAuthenticationHandler.addConstructorArgValue("/");
		}

		String tokenIdParam = element.getAttribute("token-id-param");
		if (StringUtils.hasText(tokenIdParam)) {
			authorizationEndpoint.addPropertyValue("tokenIdParameterName", tokenIdParam);
			successfulAuthenticationHandler.addPropertyValue("tokenIdParameterName", tokenIdParam);
		}

		BeanDefinitionBuilder accessTokenEndpoint = BeanDefinitionBuilder.rootBeanDefinition(AccessTokenEndpoint.class);
		if (StringUtils.hasText(tokenServicesRef)) {
			accessTokenEndpoint.addPropertyReference("tokenServices", tokenServicesRef);
		}
		String accessTokenURL = element.getAttribute("access-token-url");

		BeanDefinitionBuilder oauthProviderProcessingFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuthProviderProcessingFilter.class);
		if (StringUtils.hasText(consumerDetailsRef)) {
			oauthProviderProcessingFilterBean.addPropertyReference("consumerDetailsService", consumerDetailsRef);
		}
		if (StringUtils.hasText(tokenServicesRef)) {
			oauthProviderProcessingFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
		}

		String nonceServicesRef = element.getAttribute("nonce-services-ref");
		if (StringUtils.hasText(nonceServicesRef)) {
			oauthProviderProcessingFilterBean.addPropertyReference("nonceServices", nonceServicesRef);
		}

		String supportRef = element.getAttribute("support-ref");
		if (StringUtils.hasText(supportRef)) {
			oauthProviderProcessingFilterBean.addPropertyReference("providerSupport", supportRef);
		}

		String authHandlerRef = element.getAttribute("auth-handler-ref");
		if (StringUtils.hasText(authHandlerRef)) {
			oauthProviderProcessingFilterBean.addPropertyReference("authHandler", authHandlerRef);
		}

		String require10a = element.getAttribute("require10a");
		if (StringUtils.hasText(require10a)) {
			requestTokenEndpoint.addPropertyValue("require10a", require10a);
			accessTokenEndpoint.addPropertyValue("require10a", require10a);
			authorizationEndpoint.addPropertyValue("require10a", require10a);
			successfulAuthenticationHandler.addPropertyValue("require10a", require10a);
		}

		String verifierServicesRef = element.getAttribute("verifier-services-ref");
		if (!StringUtils.hasText(verifierServicesRef)) {
			BeanDefinitionBuilder verifierServices = BeanDefinitionBuilder.rootBeanDefinition(RandomValueVerifierServices.class);
			parserContext.getRegistry().registerBeanDefinition("oauthVerifierServices", verifierServices.getBeanDefinition());
			verifierServicesRef = "oauthVerifierServices";
		}
		authorizationEndpoint.addPropertyReference("verifierServices", verifierServicesRef);

		// register the successfulAuthenticationHandler with the AuthorizationEndpoint
		String oauthSuccessfulAuthenticationHandlerRef = "oauthSuccessfulAuthenticationHandler";
		parserContext.getRegistry().registerBeanDefinition(oauthSuccessfulAuthenticationHandlerRef, successfulAuthenticationHandler.getBeanDefinition());
		authorizationEndpoint.addPropertyReference("authenticationSuccessHandler", oauthSuccessfulAuthenticationHandlerRef);

		// register the failure handler with the AuthorizationEndpoint
		String oauthFailedAuthenticationHandlerRef = "oauthFailedAuthenticationHandler";
		parserContext.getRegistry().registerBeanDefinition(oauthFailedAuthenticationHandlerRef, failedAuthenticationHandler.getBeanDefinition());
		authorizationEndpoint.addPropertyReference("authenticationFailureHandler", oauthFailedAuthenticationHandlerRef);

		// register the endpoints
		parserContext.getRegistry().registerBeanDefinition("oauthRequestTokenEndpoint", requestTokenEndpoint.getBeanDefinition());
		parserContext.getRegistry().registerBeanDefinition("oauthAccessTokenEndpoint", accessTokenEndpoint.getBeanDefinition());
		parserContext.getRegistry().registerBeanDefinition("oauthAuthorizationEndpoint", authorizationEndpoint.getBeanDefinition());

		// Register a handler mapping that can detect the OAuth framework endpoints
		BeanDefinitionBuilder handlerMappingBean = BeanDefinitionBuilder.rootBeanDefinition(FrameworkEndpointHandlerMapping.class);
		if (StringUtils.hasText(requestTokenURL)
				|| StringUtils.hasText(accessTokenURL)
				|| StringUtils.hasText(authenticateTokenURL)) {
			ManagedMap<String, TypedStringValue> mappings = new ManagedMap<String, TypedStringValue>();
			if (StringUtils.hasText(requestTokenURL)) {
				mappings.put(OAuthConstants.DEFAULT_REQUEST_TOKEN_URL, new TypedStringValue(requestTokenURL, String.class));
			}
			if (StringUtils.hasText(accessTokenURL)) {
				mappings.put(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL, new TypedStringValue(accessTokenURL, String.class));
			}
			if (StringUtils.hasText(authenticateTokenURL)) {
				mappings.put(OAuthConstants.DEFAULT_AUTHENTICATE_TOKEN_URL, new TypedStringValue(authenticateTokenURL, String.class));
			}

			handlerMappingBean.addPropertyValue("mappings", mappings);
		}
		String oauthHandlerMappingRef = "oauthHandlerMapping";
		parserContext.getRegistry().registerBeanDefinition(oauthHandlerMappingRef, handlerMappingBean.getBeanDefinition());

		oauthProviderProcessingFilterBean.addPropertyReference("frameworkEndpointHandlerMapping", oauthHandlerMappingRef);

		List<BeanMetadataElement> filterChain = ConfigUtils.findFilterChain(parserContext, element.getAttribute("filter-chain-ref"));
		parserContext.getRegistry().registerBeanDefinition("oauthProviderProcessingFilter", oauthProviderProcessingFilterBean.getBeanDefinition());
		filterChain.add(insertIndex(filterChain), new RuntimeBeanReference("oauthProviderProcessingFilter"));

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