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

package org.springframework.security.oauth2.client.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 *
 */
public interface ClientKeyGenerator {

	/**
	 * @param resource a protected resource declaration
	 * @param authentication a user Authentication (possibly null)
	 * @return a unique key identifying an access token for this pair
	 */
	String extractKey(OAuth2ProtectedResourceDetails resource, Authentication authentication);

}
