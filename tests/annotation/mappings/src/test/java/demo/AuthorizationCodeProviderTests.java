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
package demo;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;

import sparklr.common.AbstractAuthorizationCodeProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes = Application.class)
public class AuthorizationCodeProviderTests extends AbstractAuthorizationCodeProviderTests {

	@Test
	@OAuth2ContextConfiguration(resource = MyClientWithRegisteredRedirect.class, initialize = false)
	public void testInsufficientScopeInResourceRequest() throws Exception {
		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) context.getResource();
		resource.setScope(Arrays.asList("trust"));
		approveAccessTokenGrant("http://anywhere?key=value", true);
		assertNotNull(context.getAccessToken());
		try {
			http.getForString("/admin/beans");
			fail("Should have thrown exception");
		}
		catch (InsufficientScopeException ex) {
			assertTrue("Wrong summary: " + ex, ex.getSummary().contains("scope=\"read"));
		} catch (Exception e) {
			fail("Wrong exception: " + e.getClass());
			throw e;
		}
	}

}
