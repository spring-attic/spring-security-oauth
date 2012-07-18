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
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;

public class DefaultScopeValidator implements ParametersValidator {

	public void validateParameters(Map<String, String> parameters, ClientDetails clientDetails) {
		if (parameters.containsKey("scope")) {
			if (clientDetails.isScoped()) {
				Set<String> validScope = clientDetails.getScope();
				for (String scope : OAuth2Utils.parseParameterList(parameters.get("scope"))) {
					if (!validScope.contains(scope)) {
						throw new InvalidScopeException("Invalid scope: " + scope, validScope);
					}
				}
			}
		}
	}
}