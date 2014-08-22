/*
 * Copyright 2014 the original author or authors.
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
package org.springframework.security.oauth.common;

/**
 * OAuth-related constants.
 *
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public abstract class OAuthConstants {

	/**
	 * Current OAuth version.
	 */
	public final static String OAUTH_VERSION = "1.0";

	/**
	 * Default request token end point url.
	 */
	public final static String DEFAULT_REQUEST_TOKEN_URL = "/oauth_request_token";

	/**
	 * Default access token end point url.
	 */
	public final static String DEFAULT_ACCESS_TOKEN_URL = "/oauth_access_token";

	/**
	 * Default token authorization end point url.
	 */
	public final static String DEFAULT_AUTHENTICATE_TOKEN_URL = "/oauth_authenticate_token";
}
