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

package org.springframework.security.oauth2.provider.vote;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * @author Dave Syer
 * 
 */
public class ScopeVoterTests {

	private ScopeVoter voter = new ScopeVoter();

	@Test
	public void testAbstainIfNotOAuth2() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
		assertEquals(
				AccessDecisionVoter.ACCESS_ABSTAIN,
				voter.vote(clientAuthentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_READ"))));
	}

	@Test
	public void testDenyIfOAuth2AndExplictlyDenied() throws Exception {

		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("DENY_OAUTH"))));
	}

	@Test
	public void testAccessGrantedIfScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_GRANTED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_READ"))));
	}

	@Test
	public void testAccessGrantedIfScopesPresentWithPrefix() throws Exception {
		voter.setScopePrefix("scope=");
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_GRANTED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("scope=read"))));
	}

	@Test
	public void testAccessDeniedIfWrongScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		voter.setThrowException(false);
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_WRITE"))));
	}

	@Test(expected = AccessDeniedException.class)
	public void testExceptionThrownIfWrongScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_WRITE"))));
	}
}
