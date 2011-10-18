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

package org.springframework.security.oauth2.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.filter.CompositeFilter;
import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String tokenServicesRef = element.getAttribute("token-services-ref");
		String serializerRef = element.getAttribute("serialization-service-ref");

		ManagedList<BeanMetadataElement> filters = new ManagedList<BeanMetadataElement>();

		BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
		if (StringUtils.hasText(serializerRef)) {
			exceptionHandler.addPropertyReference("serializationService", serializerRef);
		}

		parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter",
				exceptionHandler.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));

		if (!StringUtils.hasText(tokenServicesRef)) {
			tokenServicesRef = "oauth2TokenServices";
			BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder
					.rootBeanDefinition(InMemoryTokenStore.class);
			parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
		}

		BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(CompositeFilter.class);
		filterChain.addPropertyValue("filters", filters);

		Element authorizationServerElement = DomUtils.getChildElementByTagName(element, "authorization-server");
		if (authorizationServerElement!=null) {
			AuthorizationServerBeanDefinitionParser parser = new AuthorizationServerBeanDefinitionParser(tokenServicesRef);
			BeanDefinition endpointValidationFilter = parser.parse(authorizationServerElement, parserContext);
			filters.add(endpointValidationFilter);
		}
		Element resourceServerElement = DomUtils.getChildElementByTagName(element, "resource-server");
		if (resourceServerElement!=null) {
			ResourceServerBeanDefinitionParser parser = new ResourceServerBeanDefinitionParser(tokenServicesRef);
			BeanDefinition protectedReourceFilter = parser.parse(resourceServerElement, parserContext);
			filters.add(protectedReourceFilter);
		}

		return filterChain.getBeanDefinition();
	}

}
