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
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "client" element supporting client apps using {@link OAuth2RestTemplate}.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ClientBeanDefinitionParser extends AbstractBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

		BeanDefinitionBuilder clientContextFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ClientContextFilter.class);

		if (StringUtils.hasText(redirectStrategyRef)) {
			clientContextFilterBean.addPropertyReference("redirectStrategy", redirectStrategyRef);
		}

		return clientContextFilterBean.getBeanDefinition();

	}

}
