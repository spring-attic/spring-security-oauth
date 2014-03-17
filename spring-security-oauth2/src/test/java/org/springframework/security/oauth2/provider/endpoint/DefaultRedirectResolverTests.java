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
package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;

/**
 * @author Dave Syer
 */
public class DefaultRedirectResolverTests {

	private DefaultRedirectResolver resolver = new DefaultRedirectResolver();

	private BaseClientDetails client = new BaseClientDetails();

	{
		client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
	}

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

	// If only one redirect has been registered, then we should use it
	@Test
	public void testRedirectWithNoRequestedValue() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		resolver.resolveRedirect(null, client);
	}

	// If multiple redirects registered, then we should get an exception
	@Test(expected = RedirectMismatchException.class)
	public void testRedirectWithNoRequestedValueAndMultipleRegistered() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com", "http://nowhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		resolver.resolveRedirect(null, client);
	}

	@Test(expected = InvalidGrantException.class)
	public void testNoGrantType() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com", "http://nowhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		client.setAuthorizedGrantTypes(Collections.<String>emptyList());
		resolver.resolveRedirect(null, client);
	}

	@Test(expected = InvalidGrantException.class)
	public void testWrongGrantType() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com", "http://nowhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		resolver.resolveRedirect(null, client);
	}

	@Test(expected = InvalidGrantException.class)
	public void testWrongCustomGrantType() throws Exception {
		resolver.setRedirectGrantTypes(Collections.singleton("foo"));
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com", "http://nowhere.com"));
		client.setRegisteredRedirectUri(redirectUris);
		resolver.resolveRedirect(null, client);
	}

	@Test(expected = RedirectMismatchException.class)
	public void testRedirectNotMatching() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://nowhere.com"));
		String requestedRedirect = "http://anywhere.com/myendpoint";
		client.setRegisteredRedirectUri(redirectUris);
		assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
	}

	@Test(expected = RedirectMismatchException.class)
	public void testRedirectNotMatchingWithTraversal() throws Exception {
		Set<String> redirectUris = new HashSet<String>(Arrays.asList("http://anywhere.com/foo"));
		String requestedRedirect = "http://anywhere.com/foo/../bar";
		client.setRegisteredRedirectUri(redirectUris);
		assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
	}

}
