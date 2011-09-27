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

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.filter.OAuth2ProtectedResourceFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ResourceServerBeanDefinitionParser extends AbstractBeanDefinitionParser {

	private final String tokenServicesRef;

	public ResourceServerBeanDefinitionParser(String tokenServicesRef) {
		this.tokenServicesRef = tokenServicesRef;
	}
	
	@Override
	protected boolean shouldGenerateId() {
		return true;
	}

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String resourceId = element.getAttribute("resource-id");

		// TODO: add exception filter if not already present?

		// configure the protected resource filter
		BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
		protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
		if (StringUtils.hasText(resourceId)) {
			protectedResourceFilterBean.addPropertyValue("resourceId", resourceId);
		}

		return protectedResourceFilterBean.getBeanDefinition();
	}

}
