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

package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class TestUnconfirmedAuthorizationCodeAuthenticationProvider {

	private UnconfirmedAuthorizationCodeAuthenticationProvider provider = new UnconfirmedAuthorizationCodeAuthenticationProvider();

	/**
	 * test that a request with no scope can still be authenticated
	 */
	@Test
	public void testAuthenticateWithNoScope() {

		// Inject dependencies
		AuthorizationCodeServices authorizationCodeServices = EasyMock.createMock(AuthorizationCodeServices.class);
		provider.setAuthorizationCodeServices(authorizationCodeServices);
		AuthenticationManager authenticationManager = EasyMock.createMock(AuthenticationManager.class);
		provider.setAuthenticationManager(authenticationManager);

		// Set up expected calls to dependencies
		authorizationCodeServices.consumeAuthorizationCode("XYZ");
		UnconfirmedAuthorizationCodeAuthenticationToken clientAuthentication = new UnconfirmedAuthorizationCodeAuthenticationToken(
				"foo", Collections.singleton("bar"), null, "http://anywhere.com");
		Authentication userAuthentication = null;
		EasyMock.expectLastCall().andReturn(
				new UnconfirmedAuthorizationCodeAuthenticationTokenHolder(clientAuthentication, userAuthentication));

		// Set up expected calls to dependencies
		authenticationManager.authenticate((Authentication) EasyMock.anyObject());
		EasyMock.expectLastCall().andAnswer(new IAnswer<Object>() {
			public Object answer() throws Throwable {
				return EasyMock.getCurrentArguments()[0];
			}
		});

		// Finalize expected calls to dependencies
		EasyMock.replay(authorizationCodeServices, authenticationManager);

		// When a WebServerProfile initiates this request remotely the scope is not known, but the saved value in the
		// UnconfirmedAuthorizationCodeAuthenticationToken can be used
		AuthorizationCodeAuthenticationToken authentication = new AuthorizationCodeAuthenticationToken("foo", null,
				Collections.<String> emptySet(), "XYZ", "http://anywhere.com");

		// The call we are testing
		Authentication result = provider.authenticate(authentication);

		assertEquals("[bar]", ((OAuth2Authentication) result).getClientAuthentication().getScope().toString());

		EasyMock.verify(authorizationCodeServices);

	}

}
