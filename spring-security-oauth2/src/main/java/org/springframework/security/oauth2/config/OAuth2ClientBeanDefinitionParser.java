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
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientProcessingFilter;
import org.springframework.security.oauth2.client.filter.cache.HttpSessionAccessTokenCache;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.provider.filter.CompositeFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 * 
 * @author Ryan Heaton
 */
public class OAuth2ClientBeanDefinitionParser extends AbstractBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String resourceDetailsServiceRef = element.getAttribute("resource-details-service-ref");
		String tokenCacheRef = element.getAttribute("token-cache-ref");
		String accessTokenProvider = element.getAttribute("token-provider-ref");
		String requireAuthenticated = element.getAttribute("require-authenticated");
		String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");
		String redirectOnError = element.getAttribute("redirect-on-error");

		if (!StringUtils.hasText(tokenCacheRef)) {
			tokenCacheRef = "oauth2ClientTokenCache";
			BeanDefinitionBuilder rememberMeServices = BeanDefinitionBuilder
					.rootBeanDefinition(HttpSessionAccessTokenCache.class);
			parserContext.getRegistry().registerBeanDefinition(tokenCacheRef,
					rememberMeServices.getBeanDefinition());
		}

		if (!StringUtils.hasText(resourceDetailsServiceRef)) {
			resourceDetailsServiceRef = "oauth2ResourceDetailsService";
			BeanDefinitionBuilder resourceDetailsService = BeanDefinitionBuilder
					.rootBeanDefinition(ResourceDetailsServiceFactoryBean.class);
			parserContext.getRegistry().registerBeanDefinition(resourceDetailsServiceRef,
					resourceDetailsService.getBeanDefinition());
		}

		if (!StringUtils.hasText(accessTokenProvider)) {
			accessTokenProvider = "oauth2AccessTokenProvider";
			ManagedList<BeanMetadataElement> profiles = new ManagedList<BeanMetadataElement>();
			profiles.add(BeanDefinitionBuilder.genericBeanDefinition(AuthorizationCodeAccessTokenProvider.class).getBeanDefinition());
			profiles.add(BeanDefinitionBuilder.genericBeanDefinition(ClientCredentialsAccessTokenProvider.class).getBeanDefinition());
			BeanDefinitionBuilder profileManager = BeanDefinitionBuilder.rootBeanDefinition(AccessTokenProviderChain.class);
			profileManager.addConstructorArgValue(profiles);
			if ("false".equalsIgnoreCase(requireAuthenticated)) {
				profileManager.addPropertyValue("requireAuthenticated", "false");
			}
			parserContext.getRegistry().registerBeanDefinition(accessTokenProvider, profileManager.getBeanDefinition());
		}

		BeanDefinitionBuilder clientContextFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ClientContextFilter.class);
		clientContextFilterBean.addPropertyReference("accessTokenProvider", accessTokenProvider);
		clientContextFilterBean.addPropertyReference("clientTokenCache", tokenCacheRef);

		if (StringUtils.hasText(redirectOnError)) {
			clientContextFilterBean.addPropertyValue("redirectOnError", redirectOnError);
		}
		

		if (StringUtils.hasText(redirectStrategyRef)) {
			clientContextFilterBean.addPropertyReference("redirectStrategy", redirectStrategyRef);
		}

		ManagedList<BeanMetadataElement> filters = new ManagedList<BeanMetadataElement>();

		parserContext.getRegistry().registerBeanDefinition("oauth2ClientContextFilter",
				clientContextFilterBean.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ClientContextFilter"));

		BeanDefinition fids = ConfigUtils.createSecurityMetadataSource(element, parserContext);

		if (fids != null) {
			BeanDefinitionBuilder consumerFilterBean = BeanDefinitionBuilder
					.rootBeanDefinition(OAuth2ClientProcessingFilter.class);

			consumerFilterBean.addPropertyValue("objectDefinitionSource", fids);
			consumerFilterBean.addPropertyReference("resourceDetailsService", resourceDetailsServiceRef);
			parserContext.getRegistry().registerBeanDefinition("oauth2ClientSecurityFilter",
					consumerFilterBean.getBeanDefinition());
			filters.add(new RuntimeBeanReference("oauth2ClientSecurityFilter"));
		}

		BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(CompositeFilter.class);
		filterChain.addPropertyValue("filters", filters);
		return filterChain.getBeanDefinition();

	}

}
