/*
 * Copyright 2008-2009 Web Cohesion
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

package org.springframework.security.oauth2.config.xml;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "resource-server" element. Creates a filter that can be added to the standard Spring Security
 * filter chain.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ResourceServerBeanDefinitionParser extends ProviderBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef) {

		String resourceId = element.getAttribute("resource-id");
		String entryPointRef = element.getAttribute("entry-point-ref");
		String authenticationManagerRef = element.getAttribute("authentication-manager-ref");
		String tokenExtractorRef = element.getAttribute("token-extractor-ref");
		String entryAuthDetailsSource = element.getAttribute("auth-details-source-ref");
		String stateless = element.getAttribute("stateless");

		// configure the protected resource filter
		BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthenticationProcessingFilter.class);

		if (StringUtils.hasText(authenticationManagerRef)) {
			protectedResourceFilterBean.addPropertyReference("authenticationManager", authenticationManagerRef);
		}
		else {

			BeanDefinitionBuilder authenticationManagerBean = BeanDefinitionBuilder
					.rootBeanDefinition(OAuth2AuthenticationManager.class);
			
			authenticationManagerBean.addPropertyReference("tokenServices", tokenServicesRef);

			if (StringUtils.hasText(resourceId)) {
				authenticationManagerBean.addPropertyValue("resourceId", resourceId);
			}

			protectedResourceFilterBean.addPropertyValue("authenticationManager",
					authenticationManagerBean.getBeanDefinition());

		}

		if (StringUtils.hasText(entryPointRef)) {
			protectedResourceFilterBean.addPropertyReference("authenticationEntryPoint", entryPointRef);
		}

		if (StringUtils.hasText(entryAuthDetailsSource)) {
			protectedResourceFilterBean.addPropertyReference("authenticationDetailsSource", entryAuthDetailsSource);
		}

		if (StringUtils.hasText(tokenExtractorRef)) {
			protectedResourceFilterBean.addPropertyReference("tokenExtractor", tokenExtractorRef);
		}

		if (StringUtils.hasText(stateless)) {
			protectedResourceFilterBean.addPropertyValue("stateless", stateless);
		}

		return protectedResourceFilterBean.getBeanDefinition();

	}

}
