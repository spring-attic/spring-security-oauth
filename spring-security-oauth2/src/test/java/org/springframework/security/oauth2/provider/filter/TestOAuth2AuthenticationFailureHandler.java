/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.oauth2.provider.filter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.web.OAuth2ExceptionRenderer;
import org.springframework.web.context.request.ServletWebRequest;

/**
 *
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class TestOAuth2AuthenticationFailureHandler {
	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private OAuth2ExceptionRendererStub renderer;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;
	private AuthenticationException originalException;

	private OAuth2AuthenticationFailureHandler handler;

	@Before
	public void setUp() {
		renderer = new OAuth2ExceptionRendererStub();
		originalException = new UsernameNotFoundException("not found");

		handler = new OAuth2AuthenticationFailureHandler();
		handler.setExceptionRenderer(renderer);
	}

	@Test
	public void onAuthenticationFailure() throws Exception {
		handler.onAuthenticationFailure(request, response, originalException);
		Object body = renderer.entity.getBody();
		assertTrue("The entity should be an InvalidClientException. Got "+body,body instanceof InvalidClientException);
		assertEquals(HttpStatus.UNAUTHORIZED,renderer.entity.getStatusCode());
		assertSame(request,renderer.webRequest.getNativeRequest());
		assertSame(response,renderer.webRequest.getNativeResponse());
	}

	@Test
	public void setExceptionRendererNullExceptionRenderer() {
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("exceptionRenderer cannot be null");
		handler.setExceptionRenderer(null);
	}

	/**
	 * Rather than deal with EasyMock class extension just capture the arguments using this stub
	 */
	private static class OAuth2ExceptionRendererStub implements OAuth2ExceptionRenderer {
		private ResponseEntity<?> entity;
		private ServletWebRequest webRequest;
		public void handleHttpEntityResponse(HttpEntity<?> responseEntity, ServletWebRequest webRequest)
				throws Exception {
			this.entity = (ResponseEntity<?>) responseEntity;
			this.webRequest = webRequest;
		}
	}
}
