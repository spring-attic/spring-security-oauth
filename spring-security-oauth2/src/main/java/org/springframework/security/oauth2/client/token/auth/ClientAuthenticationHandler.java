/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.client.token.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

/**
 * Logic for handling client authentication.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface ClientAuthenticationHandler {

	/**
	 * Authenticate a token request.
	 * 
	 * @param resource The resource for which to authenticate a request.
	 * @param form The form that is being submitted as the token request.
	 * @param headers The request headers to be submitted.
	 */
	void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			HttpHeaders headers);
}
