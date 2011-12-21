/*
 * Copyright 2002-2011 the original author or authors.
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

package org.springframework.security.oauth2.client.http;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;

/**
 * @author Dave Syer
 *
 */
public class TestOAuth2ErrorHandler {
	
	private ClientHttpResponse response;

	@Rule
	public ExpectedException expected = ExpectedException.none();
	
	private final class TestClientHttpResponse implements ClientHttpResponse {

		private final HttpHeaders headers;

		public TestClientHttpResponse(HttpHeaders headers) {
			this.headers = headers;
			
		}

		public InputStream getBody() throws IOException {
			return null;
		}

		public HttpHeaders getHeaders() {
			return headers;
		}

		public HttpStatus getStatusCode() throws IOException {
			return null;
		}

		public String getStatusText() throws IOException {
			return null;
		}

		public void close() {
		}
	}

	private OAuth2ErrorHandler handler = new OAuth2ErrorHandler();

	@Before
	public void setUp() throws Exception {
		response = createMock(ClientHttpResponse.class);
	}

	/**
	 * test response with www-authenticate header
	 */
	@Test
	public void testHandleErrorClientHttpResponse() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.set("www-authenticate", "Bearer error=foo");
		ClientHttpResponse response = new TestClientHttpResponse(headers);

		expected.expectMessage("foo");
		handler.handleError(response);

	}

	@Test
	public void testCustomHandler() throws Exception {

		OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {
			
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return true;
			}
			
			public void handleError(ClientHttpResponse response) throws IOException {
				throw new RuntimeException("planned");
			}
		});
		
		HttpHeaders headers = new HttpHeaders();
		ClientHttpResponse response = new TestClientHttpResponse(headers);

		expected.expectMessage("planned");
		handler.handleError(response);

	}

	@Test
	public void testHandleExpiredTokenError() throws IOException {

		final HttpHeaders headers = new HttpHeaders();
		headers.add("WWW-Authenticate", OAuth2AccessToken.BEARER_TYPE + " error=invalid_token");
		response.getHeaders();
		expectLastCall().andReturn(headers);
		replay(response);

		try {
			handler.handleError(response);
		} catch (InvalidTokenException e) {
			verify(response);
			return;
		}

		fail("Expected exception was not thrown");
	}

	@Test
	public void testHandleErrorWithMissingHeader() throws IOException {

		final HttpHeaders headers = new HttpHeaders();
		response.getHeaders();
		expectLastCall().andReturn(headers).anyTimes();
		response.getStatusCode();
		expectLastCall().andReturn(HttpStatus.BAD_REQUEST);
		response.getBody();
		expectLastCall().andReturn(new ByteArrayInputStream(new byte[0]));
		response.getStatusText();
		expectLastCall().andReturn(HttpStatus.BAD_REQUEST.toString());
		replay(response);

		try {
			handler.handleError(response);
		} catch (HttpClientErrorException e) {
			verify(response);
			return;
		}

		fail("Expected exception was not thrown");
	}
}
