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

package org.springframework.security.oauth2.config.xml;

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class ClientDetailsServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return InMemoryClientDetailsService.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		List<Element> clientElements = DomUtils.getChildElementsByTagName(element, "client");
		ManagedMap<String, BeanMetadataElement> clients = new ManagedMap<String, BeanMetadataElement>();
		for (Element clientElement : clientElements) {
			BeanDefinitionBuilder client = BeanDefinitionBuilder.rootBeanDefinition(BaseClientDetails.class);
			String clientId = clientElement.getAttribute("client-id");
			if (StringUtils.hasText(clientId)) {
				client.addConstructorArgValue(clientId);
			}
			else {
				parserContext.getReaderContext().error("A client id must be supplied with the definition of a client.",
						clientElement);
			}

			String secret = clientElement.getAttribute("secret");
			if (StringUtils.hasText(secret)) {
				client.addPropertyValue("clientSecret", secret);
			}
			String resourceIds = clientElement.getAttribute("resource-ids");
			if (StringUtils.hasText(clientId)) {
				client.addConstructorArgValue(resourceIds);
			}
			else {
				client.addConstructorArgValue("");
			}
			String redirectUri = clientElement.getAttribute("redirect-uri");
			String tokenValidity = clientElement.getAttribute("access-token-validity");
			if (StringUtils.hasText(tokenValidity)) {
				client.addPropertyValue("accessTokenValiditySeconds", tokenValidity);
			}
			String refreshValidity = clientElement.getAttribute("refresh-token-validity");
			if (StringUtils.hasText(refreshValidity)) {
				client.addPropertyValue("refreshTokenValiditySeconds", refreshValidity);
			}
			client.addConstructorArgValue(clientElement.getAttribute("scope"));
			client.addConstructorArgValue(clientElement.getAttribute("authorized-grant-types"));
			client.addConstructorArgValue(clientElement.getAttribute("authorities"));
			if (StringUtils.hasText(redirectUri)) {
				client.addConstructorArgValue(redirectUri);
			}
			client.addPropertyValue("autoApproveScopes", clientElement.getAttribute("autoapprove"));

			clients.put(clientId, client.getBeanDefinition());
		}

		builder.addPropertyValue("clientDetailsStore", clients);
	}
}