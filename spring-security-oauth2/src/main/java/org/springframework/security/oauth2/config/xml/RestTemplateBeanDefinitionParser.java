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
package org.springframework.security.oauth2.config.xml;

import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Dave Syer
 * 
 */
public class RestTemplateBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return OAuth2RestTemplate.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

		String accessTokenProviderRef = element.getAttribute("access-token-provider");
		
		builder.addConstructorArgReference(element.getAttribute("resource"));

		BeanDefinitionBuilder request = BeanDefinitionBuilder.genericBeanDefinition(DefaultAccessTokenRequest.class);
		request.setScope("request");
		request.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		request.addConstructorArgValue("#{request.parameterMap}");
		request.addPropertyValue("currentUri", "#{request.getAttribute('currentUri')}");

		BeanDefinitionHolder requestDefinition = new BeanDefinitionHolder(request.getRawBeanDefinition(), parserContext
				.getReaderContext().generateBeanName(request.getRawBeanDefinition()));
		parserContext.getRegistry().registerBeanDefinition(requestDefinition.getBeanName(),
				requestDefinition.getBeanDefinition());
		BeanDefinitionHolder requestHolder = ScopedProxyUtils.createScopedProxy(requestDefinition,
				parserContext.getRegistry(), false);

		BeanDefinitionBuilder scopedContext = BeanDefinitionBuilder
				.genericBeanDefinition(DefaultOAuth2ClientContext.class);
		scopedContext.setScope("session");
		scopedContext.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		BeanDefinitionHolder contextDefinition = new BeanDefinitionHolder(scopedContext.getRawBeanDefinition(),
				parserContext.getReaderContext().generateBeanName(scopedContext.getRawBeanDefinition()));
		parserContext.getRegistry().registerBeanDefinition(contextDefinition.getBeanName(),
				contextDefinition.getBeanDefinition());
		BeanDefinitionHolder contextHolder = ScopedProxyUtils.createScopedProxy(contextDefinition,
				parserContext.getRegistry(), false);
		scopedContext.addConstructorArgValue(requestHolder.getBeanDefinition());

		BeanDefinitionBuilder bareContext = BeanDefinitionBuilder
				.genericBeanDefinition(DefaultOAuth2ClientContext.class);

		BeanDefinitionBuilder context = BeanDefinitionBuilder
				.genericBeanDefinition(OAuth2ClientContextFactoryBean.class);

		context.addPropertyValue("scopedContext", contextHolder.getBeanDefinition());
		context.addPropertyValue("bareContext", bareContext.getBeanDefinition());
		context.addPropertyReference("resource", element.getAttribute("resource"));

		builder.addConstructorArgValue(context.getBeanDefinition());
		if (StringUtils.hasText(accessTokenProviderRef)) {
			builder.addPropertyReference("accessTokenProvider", accessTokenProviderRef);
		}

		parserContext.getDelegate().parsePropertyElements(element, builder.getBeanDefinition());

	}

}
