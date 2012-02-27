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
package org.springframework.security.oauth2.provider.error;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Writes an {@link InvalidClientException} to the response using the {@link OAuth2ExceptionRenderer}.
 * 
 * @author Rob Winch
 * @author Dave Syer
 */
public final class OAuth2AuthenticationFailureHandler extends AbstractOAuth2SecurityExceptionHandler implements AuthenticationFailureHandler {
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		OAuth2Exception result;
		if (exception instanceof OAuth2Exception) {
			result = (OAuth2Exception) exception;
		}
		else {
			result = new InvalidClientException(exception.getMessage(), exception);
		}
		doHandle(request, response, result);

	}

}