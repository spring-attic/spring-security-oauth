/*
 * Copyright 20013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * @author Dave Syer
 *
 */
public class OAuth2RequestTests {

	private Map<String, String> parameters;

	@Before
	public void prepare() {
		parameters = new HashMap<String, String>();
		parameters.put("client_id", "theClient");
	}

	@Test
	public void testImplicitGrantType() throws Exception {
		parameters.put("response_type", "token");
		OAuth2Request authorizationRequest = createFromParameters(parameters);
		assertEquals("implicit", authorizationRequest.getGrantType());
	}

	@Test
	public void testOtherGrantType() throws Exception {
		parameters.put("grant_type", "password");
		OAuth2Request authorizationRequest = createFromParameters(parameters);
		assertEquals("password", authorizationRequest.getGrantType());
	}

	private OAuth2Request createFromParameters(Map<String, String> parameters) {
		OAuth2Request request = RequestTokenFactory.createOAuth2Request(parameters,
				parameters.get(OAuth2Utils.CLIENT_ID), false,
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)));
		return request;
	}

}
