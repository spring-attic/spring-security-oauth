/*
 * Copyright 2012-2013 the original author or authors.
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

package org.springframework.security.oauth2.client.token;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.AbstractClientHttpRequest;
import org.springframework.http.client.AbstractClientHttpResponse;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2AccessTokenSupportTests {

	private ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

	private HttpHeaders requestHeaders = new HttpHeaders();

	private MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();

	private StubHttpClientResponse response;

	private IOException error;

	private DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
	
	private AccessTokenRequest request = new DefaultAccessTokenRequest();

	private ObjectMapper objectMapper = new ObjectMapper();

	private OAuth2AccessTokenSupport support = new OAuth2AccessTokenSupport(){};

	@Before
	public void init() throws Exception {
		resource.setClientId("client");
		resource.setClientSecret("secret");
		resource.setAccessTokenUri("http://nowhere/token");
		response = new StubHttpClientResponse();
		support.setRequestFactory(new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				return new StubClientHttpRequest(response);
			}
		});
	}

	@Test(expected = OAuth2AccessDeniedException.class)
	public void testRetrieveTokenFailsWhenTokenEndpointNotAvailable() {
		error = new IOException("Planned");
		response.setStatus(HttpStatus.BAD_REQUEST);
		support.retrieveToken(request, resource, form, requestHeaders);
	}

	@Test
	public void testRetrieveToken() throws Exception {
		response.setBody(objectMapper.writeValueAsString(accessToken));
		OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
		assertEquals(accessToken, retrieveToken);
	}

	@Test
	public void testRetrieveTokenFormEncoded() throws Exception {
		// SECOAUTH-306: no need to set message converters
		requestHeaders.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		response.setBody("access_token=FOO");
		response.setHeaders(responseHeaders );
		OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
		assertEquals(accessToken, retrieveToken);
	}

	@Test
	public void testRequestEnhanced() throws Exception {
		DefaultRequestEnhancer enhancer = new DefaultRequestEnhancer();
		enhancer.setParameterIncludes(Arrays.asList("foo"));
		request.set("foo", "bar");
		support.setTokenRequestEnhancer(enhancer);
		response.setBody(objectMapper.writeValueAsString(accessToken));
		OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
		assertEquals("[bar]", form.get("foo").toString());
		assertEquals(accessToken, retrieveToken);
	}

	@Test
	public void testRequestNotEnhanced() throws Exception {
		request.set("foo", "bar");
		response.setBody(objectMapper.writeValueAsString(accessToken));
		OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
		assertEquals(null, form.get("foo"));
		assertEquals(accessToken, retrieveToken);
	}

	private final class StubHttpClientResponse extends AbstractClientHttpResponse {
		private HttpStatus status = HttpStatus.OK;

		private String body;

		private HttpHeaders headers = new HttpHeaders();
		
		{
			headers.setContentType(MediaType.APPLICATION_JSON);
		}
		
		public void setBody(String body) {
			this.body = body;
		}

		public void setHeaders(HttpHeaders headers) {
			this.headers = headers;
		}
		
		public void setStatus(HttpStatus status) {
			this.status = status;
		}

		public int getRawStatusCode() throws IOException {
			return status.value();
		}

		public String getStatusText() throws IOException {
			return status.toString();
		}

		public void close() {
		}

		public InputStream getBody() throws IOException {
			if (error != null) {
				throw error;
			}
			return new ByteArrayInputStream(body.getBytes());
		}

		public HttpHeaders getHeaders() {
			return headers;
		}
	}

	private static class StubClientHttpRequest extends AbstractClientHttpRequest {

		private final ClientHttpResponse response;

		public StubClientHttpRequest(ClientHttpResponse response) {
			this.response = response;
		}

		public HttpMethod getMethod() {
			return HttpMethod.GET;
		}

		public URI getURI() {
			return null;
		}

		@Override
		protected OutputStream getBodyInternal(HttpHeaders headers) throws IOException {
			return new ByteArrayOutputStream();
		}

		@Override
		protected ClientHttpResponse executeInternal(HttpHeaders headers) throws IOException {
			return response;
		}
	}

}
