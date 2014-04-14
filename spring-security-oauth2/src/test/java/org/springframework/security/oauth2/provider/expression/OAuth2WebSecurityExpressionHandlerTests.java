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

package org.springframework.security.oauth2.provider.expression;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2WebSecurityExpressionHandlerTests {

	private OAuth2WebSecurityExpressionHandler handler = new OAuth2WebSecurityExpressionHandler();

	@Test
	public void testScopesWithOr() throws Exception {
		AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
		request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "bar", "",
				"client_credentials", "ROLE_USER"));
		request.setApproved(true);
		OAuth2Request clientAuthentication = request.createOAuth2Request();
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
		Expression expression = handler.getExpressionParser().parseExpression(
				"#oauth2.hasAnyScope('write') or #oauth2.isUser()");
		assertTrue((Boolean) expression.getValue(context));
	}

	@Test
	public void testOauthClient() throws Exception {
		AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
		request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "", "",
				"client_credentials", "ROLE_CLIENT"));

		OAuth2Request clientAuthentication = RequestTokenFactory
				.createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(),
						request.isApproved(), request.getScope(), request.getResourceIds(), request.getRedirectUri(),
						request.getResponseTypes(), request.getExtensions());

		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser()
				.parseExpression("#oauth2.clientHasAnyRole('ROLE_CLIENT')");
		assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation)));
	}

	@Test
	public void testScopes() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false,
				Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('read')");
		assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation)));
	}

	@Test(expected = AccessDeniedException.class)
	public void testInsufficientScope() throws Exception {
		AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
		request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "bar", "",
				"client_credentials", "ROLE_USER"));
		OAuth2Request clientAuthentication = request.createOAuth2Request();
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
		boolean hasAnyScope = root.hasAnyScope("foo");
		root.throwOnError(hasAnyScope);
	}

	@Test
	public void testNonOauthClient() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole()");
		assertFalse((Boolean) expression.getValue(handler.createEvaluationContext(clientAuthentication, invocation)));
	}

	@Test
	public void testStandardSecurityRoot() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", null);
		assertTrue(clientAuthentication.isAuthenticated());
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser().parseExpression("isAuthenticated()");
		assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(clientAuthentication, invocation)));
	}

}
