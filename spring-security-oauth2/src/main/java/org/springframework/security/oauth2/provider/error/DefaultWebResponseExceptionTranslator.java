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
package org.springframework.security.oauth2.provider.error;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.HttpRequestMethodNotSupportedException;

/**
 * @author Dave Syer
 * 
 */
public class DefaultWebResponseExceptionTranslator implements WebResponseExceptionTranslator {

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {

		// Try to extract a SpringSecurityException from the stacktrace
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
		Exception ase = (OAuth2Exception) throwableAnalyzer.getFirstThrowableOfType(
				OAuth2Exception.class, causeChain);

		if (ase != null) {
			return handleOAuth2Exception((OAuth2Exception) ase);
		}

		ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class,
				causeChain);
		if (ase != null) {
			return handleOAuth2Exception(new UnauthorizedException(e.getMessage(), e));
		}

		ase = (AccessDeniedException) throwableAnalyzer
				.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
		if (ase instanceof AccessDeniedException) {
			return handleOAuth2Exception(new ForbiddenException(ase.getMessage(), ase));
		}

		ase = (HttpRequestMethodNotSupportedException) throwableAnalyzer
				.getFirstThrowableOfType(HttpRequestMethodNotSupportedException.class, causeChain);
		if (ase instanceof HttpRequestMethodNotSupportedException) {
			return handleOAuth2Exception(new MethodNotAllowed(ase.getMessage(), ase));
		}

		return handleOAuth2Exception(new ServerErrorException(e.getMessage(), e));

	}

	private ResponseEntity<OAuth2Exception> handleOAuth2Exception(OAuth2Exception e) throws IOException {

		int status = e.getHttpErrorCode();
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cache-Control", "no-store");
		headers.set("Pragma", "no-cache");
		if (status == HttpStatus.UNAUTHORIZED.value() || (e instanceof InsufficientScopeException)) {
			headers.set("WWW-Authenticate", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, e.getSummary()));
		}

		ResponseEntity<OAuth2Exception> response = new ResponseEntity<OAuth2Exception>(e, headers,
				HttpStatus.valueOf(status));

		return response;

	}

	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		this.throwableAnalyzer = throwableAnalyzer;
	}

	@SuppressWarnings("serial")
	private static class ForbiddenException extends OAuth2Exception {

		public ForbiddenException(String msg, Throwable t) {
			super(msg, t);
		}

		public String getOAuth2ErrorCode() {
			return "access_denied";
		}

		public int getHttpErrorCode() {
			return 403;
		}

	}

	@SuppressWarnings("serial")
	private static class ServerErrorException extends OAuth2Exception {

		public ServerErrorException(String msg, Throwable t) {
			super(msg, t);
		}

		public String getOAuth2ErrorCode() {
			return "server_error";
		}

		public int getHttpErrorCode() {
			return 500;
		}

	}

	@SuppressWarnings("serial")
	private static class UnauthorizedException extends OAuth2Exception {

		public UnauthorizedException(String msg, Throwable t) {
			super(msg, t);
		}

		public String getOAuth2ErrorCode() {
			return "unauthorized";
		}

		public int getHttpErrorCode() {
			return 401;
		}

	}

	@SuppressWarnings("serial")
	private static class MethodNotAllowed extends OAuth2Exception {

		public MethodNotAllowed(String msg, Throwable t) {
			super(msg, t);
		}

		public String getOAuth2ErrorCode() {
			return "method_not_allowed";
		}

		public int getHttpErrorCode() {
			return 405;
		}

	}
}
