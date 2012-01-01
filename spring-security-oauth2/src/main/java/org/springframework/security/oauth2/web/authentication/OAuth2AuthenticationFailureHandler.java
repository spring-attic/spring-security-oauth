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
package org.springframework.security.oauth2.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.web.OAuth2ExceptionRenderer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Writes an {@link InvalidClientException} to the response using the {@link OAuth2ExceptionRenderer}.
 *
 * @author Rob Winch
 */
public final class OAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {
	private OAuth2ExceptionRenderer exceptionRenderer = new OAuth2ExceptionRenderer();

	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		InvalidClientException result = new InvalidClientException(exception.getMessage(), exception);
		HttpStatus status = HttpStatus.valueOf(result.getHttpErrorCode());
		ResponseEntity<OAuth2Exception> responseEntity = new ResponseEntity<OAuth2Exception>(result,status);

		try {
			exceptionRenderer.handleHttpEntityResponse(responseEntity , new ServletWebRequest(request,response));
		}
		catch (Exception e) {
			throw new ServletException("Failed to render "+responseEntity, e);
		}
	}

	/**
	 * Set the {@link OAuth2ExceptionRenderer} to be used. This allows for supporting custom Media Types.
	 * @param exceptionRenderer
	 */
	public void setExceptionRenderer(OAuth2ExceptionRenderer exceptionRenderer) {
		Assert.notNull(exceptionRenderer,"exceptionRenderer cannot be null");
		this.exceptionRenderer = exceptionRenderer;
	}
}