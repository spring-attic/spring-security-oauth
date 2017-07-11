/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.discovery;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.HttpHeaders;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Joe Grandja
 */
public class ProviderDiscoveryClientTest {
	private MockWebServer server;

	@Before
	public void setUp() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
	}

	@After
	public void cleanUp() throws Exception {
		this.server.shutdown();
	}

	@Test(expected = IllegalArgumentException.class)
	public void discoverWhenProviderLocationUriInvalidThenThrowIllegalArgumentException() throws Exception {
		new ProviderDiscoveryClient("invalid-uri");
	}

	@Test
	public void discoverWhenProviderSupportsDiscoveryThenReturnProviderConfiguration() throws Exception {
		this.server.enqueue(new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(
				"	{\n" +
				"   	\"issuer\": \"https://springsecurity.uaa.run.pivotal.io/oauth/token\",\n" +
				"   	\"authorization_endpoint\": \"https://springsecurity.login.run.pivotal.io/oauth/authorize\",\n" +
				"   	\"token_endpoint\": \"https://springsecurity.login.run.pivotal.io/oauth/token\",\n" +
				"   	\"userinfo_endpoint\": \"https://springsecurity.login.run.pivotal.io/userinfo\",\n" +
				"   	\"jwks_uri\": \"https://springsecurity.login.run.pivotal.io/token_keys\"\n" +
				"	}\n"));

		ProviderDiscoveryClient client = new ProviderDiscoveryClient(this.server.url("").toString());
		ProviderConfiguration providerConfiguration = client.discover();

		assertNotNull(providerConfiguration);
		assertEquals("https://springsecurity.uaa.run.pivotal.io/oauth/token", providerConfiguration.getIssuer().toString());
		assertEquals("https://springsecurity.login.run.pivotal.io/oauth/authorize", providerConfiguration.getAuthorizationEndpoint().toString());
		assertEquals("https://springsecurity.login.run.pivotal.io/oauth/token", providerConfiguration.getTokenEndpoint().toString());
		assertEquals("https://springsecurity.login.run.pivotal.io/userinfo", providerConfiguration.getUserInfoEndpoint().toString());
		assertEquals("https://springsecurity.login.run.pivotal.io/token_keys", providerConfiguration.getJwkSetUri().toString());
	}

	@Test(expected = RestClientException.class)
	public void discoverWhenProviderDoesNotSupportDiscoveryThenThrowRestClientException() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(404));

		ProviderDiscoveryClient client = new ProviderDiscoveryClient(this.server.url("").toString());
		client.discover();
	}
}