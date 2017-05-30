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
package org.springframework.security.oauth2.provider.client;

import static java.util.Arrays.asList;
import java.util.Collection;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter.ClientCredentialsRequestMatcher;

import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;


/**
 * Tests if the matcher matches correctly various request URI-s.
 * 
 * @author Lachezar Balev
 */
@RunWith(Parameterized.class)
public class ClientCredentialsRequestMatcherTests {

	private ClientCredentialsRequestMatcher matcherToTest;

	@Parameter
	public Collection<String> paths;

	@Parameter(1)
	public String contextPath;

	@Parameter(2)
	public String requestURI;

	@Parameter(3)
	public boolean hasClientID;

	@Parameter(4)
	public Boolean expected;
	
	private static Collection<String> standardPaths = asList(
			"/oauth/token", 
			"/oauth/token_key", 
			"/oauth/check_token");
	
	// @formatter:off
	@Parameters(name = "Test for paths [{0}], context [{1}], URI [{2}]. Client id set = [{3}].")
	public static Collection<Object[]> data() {
		return asList(new Object[][] { 
			//normal
			new Object[] { standardPaths, "", "/oauth/token", TRUE, TRUE },
			//with context
			new Object[] { standardPaths, "/ctx", "/ctx/oauth/token", TRUE, TRUE },
			//with col and context
			new Object[] { standardPaths, "/ctx", "/ctx/oauth/token_key;rw", TRUE, TRUE },
			//with no client
			new Object[] { standardPaths, "", "/oauth/token", FALSE, FALSE },
			//with col
			new Object[] { standardPaths, "", "/oauth/token;xyz", TRUE, TRUE },
			//path renamed
			new Object[] { asList("/foo/bar", "/some/stuff"), "", "/foo/bar;xyz", TRUE, TRUE },
			//different paths
			new Object[] { standardPaths, "", "/foo/bar", TRUE, FALSE }
		});
	}
	// @formatter:on

	private static final String CLIENT_ID_PARAM_NAME = "client_id";

	private static final String TEST_CLIENT_ID_NAME = "What's the difference between in-laws and outlaws? Outlaws are wanted.";

	@Before
	public void setUp() {
		matcherToTest = new ClientCredentialsTokenEndpointFilter.ClientCredentialsRequestMatcher(paths);
	}

	@Test
	public void testMatches() {

		MockHttpServletRequest mockRequest = new MockHttpServletRequest("POST", requestURI);
		mockRequest.setContextPath(contextPath);

		if (hasClientID) {
			mockRequest.addParameter(CLIENT_ID_PARAM_NAME, TEST_CLIENT_ID_NAME);
		}

		Boolean actual = matcherToTest.matches(mockRequest);

		Assert.assertEquals(expected, actual);
	}

}
