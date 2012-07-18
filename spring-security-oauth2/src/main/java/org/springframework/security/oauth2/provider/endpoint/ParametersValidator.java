/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
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
