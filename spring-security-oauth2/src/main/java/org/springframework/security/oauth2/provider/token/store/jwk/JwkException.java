/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * General exception for JSON Web Key (JWK) related errors.
 *
 * @author Joe Grandja
 */
public class JwkException extends OAuth2Exception {
	private static final String SERVER_ERROR_ERROR_CODE = "server_error";
	private String errorCode = SERVER_ERROR_ERROR_CODE;
	private int httpStatus = 500;

	public JwkException(String message) {
		super(message);
	}

	public JwkException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Returns the <code>error</code> used in the <i>OAuth2 Error Response</i>
	 * sent back to the caller. The default is &quot;server_error&quot;.
	 *
	 * @return the <code>error</code> used in the <i>OAuth2 Error Response</i>
	 */
	@Override
	public String getOAuth2ErrorCode() {
		return this.errorCode;
	}

	/**
	 * Returns the Http Status used in the <i>OAuth2 Error Response</i>
	 * sent back to the caller. The default is 500.
	 *
	 * @return the <code>Http Status</code> set on the <i>OAuth2 Error Response</i>
	 */
	@Override
	public int getHttpErrorCode() {
		return this.httpStatus;
	}
}