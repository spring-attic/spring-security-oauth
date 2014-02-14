/*
 * Copyright 2008 Web Cohesion
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

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2SecurityNamespaceHandler extends NamespaceHandlerSupport {

	public void init() {
		registerBeanDefinitionParser("authorization-server", new AuthorizationServerBeanDefinitionParser());
		registerBeanDefinitionParser("resource-server", new ResourceServerBeanDefinitionParser());
		registerBeanDefinitionParser("client-details-service", new ClientDetailsServiceBeanDefinitionParser());
		registerBeanDefinitionParser("client", new ClientBeanDefinitionParser());
		registerBeanDefinitionParser("resource", new ResourceBeanDefinitionParser());
		registerBeanDefinitionParser("rest-template", new RestTemplateBeanDefinitionParser());
		registerBeanDefinitionParser("expression-handler", new ExpressionHandlerBeanDefinitionParser());
		registerBeanDefinitionParser("web-expression-handler", new WebExpressionHandlerBeanDefinitionParser());
	}
}