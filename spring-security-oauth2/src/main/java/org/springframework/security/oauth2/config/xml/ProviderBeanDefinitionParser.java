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
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class ProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String tokenServicesRef = element.getAttribute("token-services-ref");
		String serializerRef = element.getAttribute("serialization-service-ref");

		if (!StringUtils.hasText(tokenServicesRef)) {
			tokenServicesRef = "oauth2TokenServices";
			BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(DefaultTokenServices.class);
			AbstractBeanDefinition tokenStore = BeanDefinitionBuilder.rootBeanDefinition(InMemoryTokenStore.class).getBeanDefinition();
			tokenServices.addPropertyValue("tokenStore", tokenStore);
			parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
		}

		return parseEndpointAndReturnFilter(element, parserContext, tokenServicesRef, serializerRef);
	}

	protected abstract AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef);

}
