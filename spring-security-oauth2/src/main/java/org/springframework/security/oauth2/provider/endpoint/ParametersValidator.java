/*
 * Copyright 2006-2011 the original author or authors.
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


package org.springframework.security.oauth2.provider.endpoint;

import java.util.Map;

import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Validates parameters such as scope values requested by a client application.
 * 
 * @author Dave Syer
 * 
 */
public interface ParametersValidator {

	/**
	 * <p>
	 * Validate the parameters provided by the client. Called by the {@link AuthorizationEndpoint} and also by the
	 * {@link TokenEndpoint} before a response is sent back to the client. Note that during an authorization code flow
	 * both endpoints will call this method, but the TokenEndpoint in that case has very little if anything to validate
	 * since all the parameters neeeded for the access token were provided to the AuthorizationEndpoint.
	 * </p>
	 * 
	 * <p>
	 * Implementations should at a minimum check that the scope values requested are legal for the client.
	 * </p>
	 * 
	 * @param parameters the request parameters
	 * @param clientDetails the client requesting the token
	 */
	void validateParameters(Map<String, String> parameters, ClientDetails clientDetails);

}
