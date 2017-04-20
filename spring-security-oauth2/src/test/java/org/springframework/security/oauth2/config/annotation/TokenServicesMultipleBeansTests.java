/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.oauth2.config.annotation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.TokenServicesMultipleBeansTests.BrokenOAuthApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * @author Dave Syer
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes=BrokenOAuthApplication.class)
@WebAppConfiguration
public class TokenServicesMultipleBeansTests {
	
	@Autowired(required=false)
	private ResourceServerTokenServices tokenServices;

	@Autowired
	private AuthorizationServerTokenServices authServerTokenServices;

	@Autowired
	private ConsumerTokenServices consumerTokenServices;

	@Test
	public void test() {
		assertNull(tokenServices);
		assertNotNull(authServerTokenServices);
		assertNotNull(consumerTokenServices);
	}

	@Configuration
	@EnableAuthorizationServer
	@EnableResourceServer
	@EnableWebSecurity
	protected static class BrokenOAuthApplication extends AuthorizationServerConfigurerAdapter {
	}
}
