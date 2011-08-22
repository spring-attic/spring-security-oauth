/*
 * Copyright 2006-2010 the original author or authors.
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

package org.springframework.security.oauth2.provider;

import javax.servlet.RequestDispatcher;

import org.junit.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;

/**
 * @author Dave Syer
 *
 */
public class TestBootstrap {
	
	@Test
	public void testRootContext() throws Exception {
		GenericXmlApplicationContext context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/applicationContext.xml"));
		context.close();
	}

	@Test
	public void testServletContext() throws Exception {
		GenericXmlApplicationContext parent = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/applicationContext.xml"));
		GenericWebApplicationContext context = new GenericWebApplicationContext();
		MockServletContext servletContext = new MockServletContext() {
			@Override
			public RequestDispatcher getNamedDispatcher(String path) {
				return new MockRequestDispatcher("foo");
			}
		};
		context.setServletContext(servletContext);
		servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
		DefaultListableBeanFactory beanFactory = context.getDefaultListableBeanFactory();
		beanFactory.setParentBeanFactory(parent.getDefaultListableBeanFactory());
		new XmlBeanDefinitionReader(context).loadBeanDefinitions(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		context.refresh();
		context.close();
		parent.close();
	}

}
