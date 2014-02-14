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
package org.springframework.security.oauth2.config.annotation;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

/**
 * @author Dave Syer
 * 
 */
@RunWith(Parameterized.class)
public class TestAuthorizationServerConfiguration {

	private AnnotationConfigWebApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Parameters
	public static List<Object[]> parameters() {
		return Arrays.asList(new Object[] { AuthorizationServerVanilla.class },
				new Object[] { AuthorizationServerExtras.class }, new Object[] { AuthorizationServerTypes.class });
	}

	public TestAuthorizationServerConfiguration(Class<?> resource) {
		context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(resource);
		context.refresh();
	}

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void testDefaults() {
		assertTrue(context.containsBeanDefinition("authorizationEndpoint"));
	}
	
	@Configuration
	@EnableWebMvcSecurity
	protected static class AuthorizationServerVanilla extends OAuth2AuthorizationServerConfigurerAdapter {
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
	        http
	            .authorizeRequests()
	                .antMatchers("/oauth/token").fullyAuthenticated()
	                .and()
	            .requestMatchers()
                    .antMatchers("/oauth/token")
                    .and()
	            .apply(new OAuth2AuthorizationServerConfigurer());
	    	// @formatter:on
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	protected static class AuthorizationServerExtras extends OAuth2AuthorizationServerConfigurerAdapter {
		
		private TokenStore tokenStore = new InMemoryTokenStore();

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
	        http
	            .authorizeRequests()
	                .antMatchers("/oauth/token").fullyAuthenticated()
	                .and()
	            .requestMatchers()
                    .antMatchers("/oauth/token")
                    .and()
	            .apply(new OAuth2AuthorizationServerConfigurer())
	                .tokenStore(tokenStore)
	                .authenticationManager(super.authenticationManagerBean())
	                .realm("sparklr2/client");
	    	// @formatter:on
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	protected static class AuthorizationServerTypes  extends OAuth2AuthorizationServerConfigurerAdapter {
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// TODO: actually configure a token granter
			// @formatter:off
	        http
	            .authorizeRequests()
	                .antMatchers("/oauth/token").fullyAuthenticated()
	                .and()
	            .requestMatchers()
                    .antMatchers("/oauth/token")
                    .and()
	            .apply(new OAuth2AuthorizationServerConfigurer());
	    	// @formatter:on
		}

	}

}
