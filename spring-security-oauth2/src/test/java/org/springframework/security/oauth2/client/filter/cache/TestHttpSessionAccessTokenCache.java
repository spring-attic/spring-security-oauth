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
package org.springframework.security.oauth2.client.filter.cache;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Collections;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 */
public class TestHttpSessionAccessTokenCache {
	
	private HttpSessionAccessTokenCache services = new HttpSessionAccessTokenCache();
	
	private MockHttpServletRequest request = new MockHttpServletRequest();
	
	private MockHttpServletResponse response = new MockHttpServletResponse();
	
	@Test
	public void testSaveTokensCreatesSessionByDefault() throws Exception {
		assertNull(request.getSession(false));
		services.rememberTokens(Collections.<OAuth2ProtectedResourceDetails,OAuth2AccessToken>emptyMap(), request, response);
		assertNotNull(request.getSession(false));
	}
}
