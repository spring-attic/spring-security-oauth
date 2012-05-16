/*
 * Copyright 2006-2011 the original author or authors.
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

import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.context.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.w3c.dom.Element;

/**
 * @author Dave Syer
 * 
 */
public class RestTemplateBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return OAuth2RestTemplateFactoryBean.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

		builder.addPropertyReference("resource", element.getAttribute("resource"));

		BeanDefinitionBuilder request = BeanDefinitionBuilder.genericBeanDefinition(DefaultAccessTokenRequest.class);
		request.setScope("request");
		request.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		request.addConstructorArgValue("#{request.parameterMap}");
		request.addPropertyValue("currentUri", "#{request.getAttribute('currentUri')}");

		BeanDefinitionHolder requestHolder = ScopedProxyUtils.createScopedProxy(
				new BeanDefinitionHolder(request.getRawBeanDefinition(), parserContext.getReaderContext()
						.generateBeanName(request.getRawBeanDefinition())), parserContext.getRegistry(), false);

		BeanDefinitionBuilder scopedContext = BeanDefinitionBuilder.genericBeanDefinition(DefaultOAuth2ClientContext.class);
		scopedContext.setScope("session");
		scopedContext.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		BeanDefinitionHolder contextHolder = ScopedProxyUtils.createScopedProxy(
				new BeanDefinitionHolder(scopedContext.getRawBeanDefinition(), parserContext.getReaderContext()
						.generateBeanName(scopedContext.getRawBeanDefinition())), parserContext.getRegistry(), false);
		scopedContext.addConstructorArgValue(requestHolder.getBeanDefinition());

		BeanDefinitionBuilder bareContext = BeanDefinitionBuilder.genericBeanDefinition(DefaultOAuth2ClientContext.class);

		builder.addPropertyValue("scopedContext", contextHolder.getBeanDefinition());
		builder.addPropertyValue("bareContext", bareContext.getBeanDefinition());

		parserContext.getDelegate().parsePropertyElements(element, builder.getBeanDefinition());

	}

}
