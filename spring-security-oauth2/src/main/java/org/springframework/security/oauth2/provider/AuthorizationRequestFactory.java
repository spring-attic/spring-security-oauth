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

package org.springframework.security.oauth2.provider;

import java.util.Map;

/**
 * Strategy for a factory of AuthorizationRequest instances during a token grant. Typical implementations would load the
 * client details from the client id provided and validate the grant type and scopes, populating any fields in the
 * request that are known only to the authorization server.
 * 
 * @author Dave Syer
 * 
 */
public interface AuthorizationRequestFactory {

	AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters);

}