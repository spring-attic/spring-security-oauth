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

package org.springframework.security.oauth.config;

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth.provider.InMemoryConsumerDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * @author Ryan Heaton
 * @author Andrew McCall
 * @author Dave Syer
 */
public class ConsumerServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return InMemoryConsumerDetailsService.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		List<Element> consumerElements = DomUtils.getChildElementsByTagName(element, "consumer");
		ManagedMap<String, BeanMetadataElement> consumers = new ManagedMap<String, BeanMetadataElement>();
		for (Object item : consumerElements) {

			BeanDefinitionBuilder consumer = BeanDefinitionBuilder
					.genericBeanDefinition(ConsumerDetailsFactoryBean.class);
			Element consumerElement = (Element) item;
			String key = consumerElement.getAttribute("key");
			if (StringUtils.hasText(key)) {
				consumer.addPropertyValue("consumerKey", key);
			}
			else {
				parserContext.getReaderContext().error(
						"A consumer key must be supplied with the definition of a consumer.", consumerElement);
			}

			String secret = consumerElement.getAttribute("secret");
			if (StringUtils.hasText(secret)) {
				consumer.addPropertyValue("secret", secret);
				String typeOfSecret = consumerElement.getAttribute("typeOfSecret");
				consumer.addPropertyValue("typeOfSecret", typeOfSecret);
			}
			else {
				parserContext.getReaderContext().error(
						"A consumer secret must be supplied with the definition of a consumer.", consumerElement);
			}

			String name = consumerElement.getAttribute("name");
			if (StringUtils.hasText(name)) {
				consumer.addPropertyValue("consumerName", name);
			}

			String authorities = consumerElement.getAttribute("authorities");
			if (StringUtils.hasText(authorities)) {
				consumer.addPropertyValue("authorities", authorities);
			}

			String resourceName = consumerElement.getAttribute("resourceName");
			if (StringUtils.hasText(resourceName)) {
				consumer.addPropertyValue("resourceName", resourceName);
			}

			String resourceDescription = consumerElement.getAttribute("resourceDescription");
			if (StringUtils.hasText(resourceDescription)) {
				consumer.addPropertyValue("resourceDescription", resourceDescription);
			}

			String requiredToObtainAuthenticatedToken = consumerElement
					.getAttribute("requiredToObtainAuthenticatedToken");
			if (StringUtils.hasText(requiredToObtainAuthenticatedToken)) {
				consumer.addPropertyValue("requiredToObtainAuthenticatedToken", requiredToObtainAuthenticatedToken);
			}

			consumers.put(key, consumer.getBeanDefinition());
		}

		builder.addPropertyValue("consumerDetailsStore", consumers);
	}
}
