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

package org.springframework.security.oauth2.client.token;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.AbstractClientHttpResponse;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2AccessTokenSupport {

	private OAuth2AccessTokenSupport support = new OAuth2AccessTokenSupport() {
	};

	private ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

	private HttpHeaders requestHeaders = new HttpHeaders();

	private MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();

	private StubHttpClientResponse response;

	private IOException error;

	private DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");

	private ObjectMapper objectMapper = new ObjectMapper();

	@Before
	public void init() throws Exception {
		resource.setClientId("client");
		resource.setClientSecret("secret");
		resource.setAccessTokenUri("http://nowhere/token");
		support.setRestTemplate(new RestTemplate() {

			@Override
			protected <T> T doExecute(URI url, HttpMethod method, RequestCallback requestCallback,
					ResponseExtractor<T> responseExtractor) throws RestClientException {
				try {
					return responseExtractor.extractData(response);
				}
				catch (IOException e) {
					throw new RestClientException("Failed", e);
				}
			}

		});
		response = new StubHttpClientResponse();
	}

	@Test(expected = OAuth2AccessDeniedException.class)
	public void testRetrieveTokenFailsWhenTokenEndpointNotAvailable() {
		error = new IOException("Planned");
		support.retrieveToken(form, requestHeaders, resource);
	}

	@Test
	public void testRetrieveToken() throws Exception {
		response.setBody(objectMapper.writeValueAsString(accessToken));
		OAuth2AccessToken retrieveToken = support.retrieveToken(form, requestHeaders, resource);
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
		OAuth2AccessToken retrieveToken = support.retrieveToken(form, requestHeaders, resource);
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

}
