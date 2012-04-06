/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.config;

import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
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
		return OAuth2RestTemplate.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

		builder.addConstructorArgReference(element.getAttribute("resource"));

		BeanDefinitionBuilder request = BeanDefinitionBuilder.genericBeanDefinition(DefaultAccessTokenRequest.class);
		request.setScope("request");
		request.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		request.addConstructorArgValue("#{request.parameterMap}");
		request.addPropertyValue("currentUri", "#{request.getAttribute('currentUri')}");

		BeanDefinitionHolder requestHolder = ScopedProxyUtils.createScopedProxy(
				new BeanDefinitionHolder(request.getRawBeanDefinition(), parserContext.getReaderContext()
						.generateBeanName(request.getRawBeanDefinition())), parserContext.getRegistry(), false);

		BeanDefinitionBuilder context = BeanDefinitionBuilder.genericBeanDefinition(DefaultOAuth2ClientContext.class);
		context.setScope("session");
		context.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		BeanDefinitionHolder contextHolder = ScopedProxyUtils.createScopedProxy(
				new BeanDefinitionHolder(context.getRawBeanDefinition(), parserContext.getReaderContext()
						.generateBeanName(context.getRawBeanDefinition())), parserContext.getRegistry(), false);
		context.addConstructorArgValue(requestHolder.getBeanDefinition());

		builder.addConstructorArgValue(contextHolder.getBeanDefinition());

		parserContext.getDelegate().parsePropertyElements(element, builder.getBeanDefinition());

	}

}
