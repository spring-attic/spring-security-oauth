/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.config.xml;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.io.ByteArrayResource;

/**
 * @author Dave Syer
 * 
 */
public class InvalidResourceBeanDefinitionParserTests {
	
	private ConfigurableApplicationContext context;
	
	@Rule
	public ExpectedException expected = ExpectedException.none();
	
	@After
	public void close() {
		if (context!=null) {
			context.close();
		}
	}

	@Test
	public void testMissingTokenUriForClientCredentials() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("accessTokenUri must be supplied");
		loadContext("type='client_credentials'");
	}

	@Test
	public void testMissingAuthorizationUriForImplicit() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("authorization URI must be supplied");
		loadContext("type='implicit'");
	}

	@Test
	public void testMissingAuthorizationUriForAuthorizationCode() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("authorization URI must be supplied");
		loadContext("type='authorization_code' access-token-uri='http://somewhere.com'");
	}

	@Test
	public void testMissingUsernameForPassword() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("A username must be supplied on a resource element of type password");
		loadContext("type='password' access-token-uri='http://somewhere.com'");
	}

	@Test
	public void testMissingPasswordForPassword() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("A password must be supplied on a resource element of type password");
		loadContext("type='password' username='admin' access-token-uri='http://somewhere.com'");
	}

	private void loadContext(String attributes) {
		String config = HEADER + String.format(TEMPLATE, attributes) + FOOTER;
		context = new GenericXmlApplicationContext(new ByteArrayResource(config .getBytes()));
	}

	private static String HEADER = "<?xml version='1.0' encoding='UTF-8'?><beans xmlns='http://www.springframework.org/schema/beans' xmlns:oauth='http://www.springframework.org/schema/security/oauth2' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'	xsi:schemaLocation='http://www.springframework.org/schema/security/oauth2 http://www.springframework.org/schema/security/spring-security-oauth2-1.0.xsd	http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd'>";
	private static String FOOTER = "</beans>";
	private static String TEMPLATE = "<oauth:resource id='resource' client-id='client' %s/>";
}
