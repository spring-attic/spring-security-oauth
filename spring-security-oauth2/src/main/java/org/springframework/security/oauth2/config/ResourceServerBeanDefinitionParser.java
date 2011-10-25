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
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.error.DefaultProviderExceptionHandler;
import org.springframework.security.oauth2.provider.filter.CompositeFilter;
import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter;
import org.springframework.security.oauth2.provider.filter.OAuth2ProtectedResourceFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ResourceServerBeanDefinitionParser extends ProviderBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef) {

		ManagedList<BeanMetadataElement> filters = new ManagedList<BeanMetadataElement>();

		BeanDefinitionBuilder exceptionHandlerFilter = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
		if (StringUtils.hasText(serializerRef)) {
			BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder
					.rootBeanDefinition(DefaultProviderExceptionHandler.class);
			exceptionHandler.addPropertyReference("serializationService", serializerRef);
			exceptionHandlerFilter.addPropertyValue("providerExceptionHandler", exceptionHandler.getBeanDefinition());
		}

		parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter",
				exceptionHandlerFilter.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));

		String resourceId = element.getAttribute("resource-id");

		// configure the protected resource filter
		BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
		protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
		if (StringUtils.hasText(resourceId)) {
			protectedResourceFilterBean.addPropertyValue("resourceId", resourceId);
		}

		parserContext.getRegistry().registerBeanDefinition("oauth2ProtectedResourceFilter",
				protectedResourceFilterBean.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ProtectedResourceFilter"));

		BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(CompositeFilter.class);
		filterChain.addPropertyValue("filters", filters);
		return filterChain.getBeanDefinition();

	}

}
