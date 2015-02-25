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

import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResponseErrorHandler;

/**
 * @author Dave Syer
 * @author Rob Winch
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2ErrorHandlerTests {

	@Mock
	private ClientHttpResponse response;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();

	private final class TestClientHttpResponse implements ClientHttpResponse {

		private final HttpHeaders headers;

		private final HttpStatus status;

		private final InputStream body;

		public TestClientHttpResponse(HttpHeaders headers, int status) {
			this(headers, status, new ByteArrayInputStream(new byte[0]));
		}

		public TestClientHttpResponse(HttpHeaders headers, int status, InputStream bodyStream) {
			this.headers = headers;
			this.status = HttpStatus.valueOf(status);
			this.body = bodyStream;
		}

		public InputStream getBody() throws IOException {
			return body;
		}

		public HttpHeaders getHeaders() {
			return headers;
		}

		public HttpStatus getStatusCode() throws IOException {
			return status;
		}

		public String getStatusText() throws IOException {
			return status.getReasonPhrase();
		}

		public int getRawStatusCode() throws IOException {
			return status.value();
		}

		public void close() {
		}
	}

	private OAuth2ErrorHandler handler = new OAuth2ErrorHandler(resource);

	/**
	 * test response with www-authenticate header
	 */
	@Test
	public void testHandleErrorClientHttpResponse() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.set("www-authenticate", "Bearer error=foo");
		ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

		// We lose the www-authenticate content in a nested exception (but it's still available) through the
		// HttpClientErrorException
		expected.expectMessage("401 Unauthorized");
		handler.handleError(response);

	}

	@Test
	public void testHandleErrorWithInvalidToken() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.set("www-authenticate", "Bearer error=\"invalid_token\", description=\"foo\"");
		ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

		expected.expect(AccessTokenRequiredException.class);
		expected.expectMessage("OAuth2 access denied");
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
		}, resource);

		HttpHeaders headers = new HttpHeaders();
		ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

		expected.expectMessage("planned");
		handler.handleError(response);

	}

	@Test
	public void testHandle500Error() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		ClientHttpResponse response = new TestClientHttpResponse(headers, 500);

		expected.expect(HttpServerErrorException.class);
		handler.handleError(response);
	}

	@Test
	public void testHandleGeneric400Error() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		ClientHttpResponse response = new TestClientHttpResponse(headers, 400);

		expected.expect(HttpClientErrorException.class);
		handler.handleError(response);
	}

	@Test
	public void testHandleGeneric403Error() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		ClientHttpResponse response = new TestClientHttpResponse(headers, 403);

		expected.expect(HttpClientErrorException.class);
		handler.handleError(response);
	}

	@Test
	// See https://github.com/spring-projects/spring-security-oauth/issues/387
	public void testHandleGeneric403ErrorWithBody() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		ClientHttpResponse response = new TestClientHttpResponse(headers, 403,
				new ByteArrayInputStream("{}".getBytes()));
		handler = new OAuth2ErrorHandler(new DefaultResponseErrorHandler(), resource);
		expected.expect(HttpClientErrorException.class);
		handler.handleError(response);
	}

	@Test
	public void testBodyCanBeUsedByCustomHandler() throws Exception {
		final String appSpecificBodyContent = "{\"some_status\":\"app error\"}";
		OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return true;
			}

			public void handleError(ClientHttpResponse response) throws IOException {
				InputStream body = response.getBody();
				byte[] buf = new byte[appSpecificBodyContent.length()];
				int readResponse = body.read(buf);
				Assert.assertEquals(buf.length, readResponse);
				Assert.assertEquals(appSpecificBodyContent, new String(buf, "UTF-8"));
				throw new RuntimeException("planned");
			}
		}, resource);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Length", "" + appSpecificBodyContent.length());
		headers.set("Content-Type", "application/json");
		InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
		ClientHttpResponse response = new TestClientHttpResponse(headers, 400, appSpecificErrorBody);

		expected.expectMessage("planned");
		handler.handleError(response);
	}

	@Test
	public void testHandleErrorWithMissingHeader() throws IOException {

		final HttpHeaders headers = new HttpHeaders();
		when(response.getHeaders()).thenReturn(headers);
		when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);
		when(response.getBody()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(response.getStatusText()).thenReturn(HttpStatus.BAD_REQUEST.toString());

		expected.expect(HttpClientErrorException.class);
		handler.handleError(response);
	}
}
