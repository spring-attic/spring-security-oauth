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
package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.BaseClientDetails;

/**
 * @author Dave Syer
 *
 */
public class TestExactMatchRedirectResolver {

	private ExactMatchRedirectResolver resolver = new ExactMatchRedirectResolver();
	private BaseClientDetails client = new BaseClientDetails();

	@Test(expected=RedirectMismatchException.class)
	public void testRedirectNotMatching() throws Exception {
		String registeredRedirect = "http://anywhere.com";
		String requestedRedirect = "http://anywhere.com/myendpoint";
		client.setRegisteredRedirectUri(registeredRedirect);
		assertEquals(registeredRedirect, resolver.resolveRedirect(requestedRedirect, client));
	}

	@Test
	public void testRedirectWithNoRegisteredValue() throws Exception {
		String requestedRedirect = "http://anywhere.com/myendpoint";
		assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
	}

	@Test
	// TODO: should be an error?  Or do we let the endpoint test that?
	public void testRedirectWithNoRequestedValue() throws Exception {
		String requestedRedirect = "http://anywhere.com";
		client.setRegisteredRedirectUri(requestedRedirect);
		assertEquals(requestedRedirect, resolver.resolveRedirect(null, client));
	}

}
