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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Dave Syer
 * 
 */
public class ResourceServerBeanDefinitionParserTests {

	@Test
	public void testDefaults() {
		GenericXmlApplicationContext context = new GenericXmlApplicationContext(
				getClass(), "resource-server-context.xml");
		assertTrue(context.containsBeanDefinition("oauth2ProviderFilter"));
		assertTrue(context.containsBeanDefinition("anotherProviderFilter"));
		assertTrue(context.containsBeanDefinition("thirdProviderFilter"));
		context.close();
	}

	@Test
	public void testAuthenticationManager() {
		GenericXmlApplicationContext context = new GenericXmlApplicationContext(
				getClass(), "resource-server-authmanager-context.xml");
		// System.err.println(Arrays.asList(context.getBeanDefinitionNames()));
		assertTrue(context.containsBeanDefinition("oauth2ProviderFilter"));
		OAuth2AuthenticationProcessingFilter filter = context.getBean(OAuth2AuthenticationProcessingFilter.class);
		assertEquals(context.getBean(AuthenticationManager.class), ReflectionTestUtils.getField(filter, "authenticationManager"));
		assertNotNull(ReflectionTestUtils.getField(filter, "tokenExtractor"));
		context.close();
	}
}