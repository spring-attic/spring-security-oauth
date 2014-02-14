/*
 * Copyright 2009 Andrew McCall
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.provider.filter;

import org.junit.Test;
import org.springframework.security.oauth.provider.filter.UserAuthorizationProcessingFilter;
import org.springframework.security.oauth.provider.filter.UserAuthorizationSuccessfulAuthenticationHandler;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.RedirectStrategy;

/**
 * @author Andrew McCall
 */
public class UserAuthorizationSuccessfulAuthenticationHandlerTests {

	/**
	 * test determineTargetUrl
	 */
	@Test
	public void testAuthenticationSuccess() throws Exception {

		UserAuthorizationSuccessfulAuthenticationHandler handler = new UserAuthorizationSuccessfulAuthenticationHandler();
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
		handler.setRedirectStrategy(redirectStrategy);

		when(request.getAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE)).thenReturn(
				"http://my.host.com/my/context");
		when(request.getAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE)).thenReturn("myver");
		when(request.getParameter("requestToken")).thenReturn("mytok");


		handler.onAuthenticationSuccess(request, response, null);

		verify(redirectStrategy).sendRedirect(request, response,
				"http://my.host.com/my/context?oauth_token=mytok&oauth_verifier=myver");

		handler = new UserAuthorizationSuccessfulAuthenticationHandler();
		handler.setRedirectStrategy(redirectStrategy);

		when(request.getAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE)).thenReturn(
				"http://my.hosting.com/my/context?with=some&query=parameter");
		when(request.getAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE)).thenReturn("myvera");
		when(request.getParameter("requestToken")).thenReturn("mytoka");

		handler.onAuthenticationSuccess(request, response, null);

		verify(redirectStrategy).sendRedirect(request, response,
				"http://my.hosting.com/my/context?with=some&query=parameter&oauth_token=mytoka&oauth_verifier=myvera");
	}
}
