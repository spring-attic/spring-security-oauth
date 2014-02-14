/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider.filter;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.util.ArrayList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.filter.AccessTokenProcessingFilter;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

/**
 * @author Ryan Heaton
 */
@RunWith(MockitoJUnitRunner.class)
public class AccessTokenProcessingFilterTests {
	@Mock
	private ConsumerDetails consumerDetails;
	@Mock
	private OAuthProviderTokenServices tokenServices;
	@Mock
	private OAuthAccessProviderToken token;

	/**
	 * tests creating the oauth token.
	 */
	@Test
	public void testCreateOAuthToken() throws Exception {
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());

		AccessTokenProcessingFilter filter = new AccessTokenProcessingFilter();
		filter.setTokenServices(tokenServices);

		when(tokenServices.createAccessToken("tok")).thenReturn(token);
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds);
		assertSame(token, filter.createOAuthToken(authentication));
	}

	/**
	 * tests the logic on a new timestamp.
	 */
	@Test
	public void testOnNewTimestamp() throws Exception {
		try {
			new AccessTokenProcessingFilter().onNewTimestamp();
			fail();
		} catch (InvalidOAuthParametersException e) {
			// fall through
		}
	}

}
