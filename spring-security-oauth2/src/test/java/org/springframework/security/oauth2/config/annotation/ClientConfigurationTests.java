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

import javax.annotation.Resource;

import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * @author Dave Syer
 * 
 */
public class ClientConfigurationTests {

	@Test
	public void testAuthCodeRedirect() throws Exception {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(ClientContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(new OAuth2ClientContextFilter()).build();
		mvc.perform(MockMvcRequestBuilders.get("/photos"))
				.andExpect(MockMvcResultMatchers.status().isFound())
				.andExpect(
						MockMvcResultMatchers.header().string("Location",
								CoreMatchers.startsWith("http://example.com/authorize")));
		context.close();
	}

	@Controller
	@Configuration
	@EnableWebMvc
	@Import(OAuth2ClientConfiguration.class)
	protected static class ClientContext {

		@Resource
		@Qualifier("accessTokenRequest")
		private AccessTokenRequest accessTokenRequest;

		@RequestMapping("/photos")
		@ResponseBody
		public String photos() {
			return restTemplate().getForObject("http://example.com/photos", String.class);
		}

		@Bean
		@Lazy
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2RestOperations restTemplate() {
			AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
			resource.setClientId("client");
			resource.setAccessTokenUri("http://example.com/token");
			resource.setUserAuthorizationUri("http://example.com/authorize");
			return new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext(accessTokenRequest));
		}

	}

}