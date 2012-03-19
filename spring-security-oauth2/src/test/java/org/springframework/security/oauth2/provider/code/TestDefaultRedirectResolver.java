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

import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;

/**
 * @author Dave Syer
 */
public class TestDefaultRedirectResolver {

	private DefaultRedirectResolver resolver = new DefaultRedirectResolver();
	private BaseClientDetails client = new BaseClientDetails();

	@Test
	public void testRedirectMatchesRegisteredValue() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		String requestedRedirect = "http://anywhere.com/myendpoint";
		assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
	}

	@Test
	public void testRedirectWithNoRegisteredValue() throws Exception {
		String requestedRedirect = "http://anywhere.com/myendpoint";
		assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
	}

	// TODO: should be an error?  Or do we let the endpoint test that?
	// If one or more redirects have been registered, then we should expect an OAuth2Exception
	@Test ( expected = OAuth2Exception.class )
	public void testRedirectWithNoRequestedValue() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		resolver.resolveRedirect(null, client);
	}

	@Test ( expected = RedirectMismatchException.class )
	public void testRedirectNotMatching() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://nowhere.com"));
		String requestedRedirect = "http://anywhere.com/myendpoint";
		client.setRegisteredRedirectUri(redirectUris);
		assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
	}

}
