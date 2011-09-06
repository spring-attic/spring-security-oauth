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

import java.io.IOException;
import java.io.InputStream;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;

/**
 * @author Dave Syer
 *
 */
public class TestOAuth2ErrorHandler {
	
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

}
