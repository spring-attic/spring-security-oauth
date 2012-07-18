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
import org.springframework.expression.Expression;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2WebSecurityExpressionHandler {

	private OAuth2WebSecurityExpressionHandler handler = new OAuth2WebSecurityExpressionHandler();

	@Test
	public void testOauthClient() throws Exception {
		DefaultAuthorizationRequest clientAuthentication = new DefaultAuthorizationRequest("foo", Collections.singleton("read"));
		clientAuthentication.addClientDetails(new BaseClientDetails("foo", "", "", "client_credentials", "ROLE_CLIENT"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole('ROLE_CLIENT')");
		assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation)));
	}

	@Test
	public void testScopes() throws Exception {
		AuthorizationRequest clientAuthentication = new DefaultAuthorizationRequest("foo", Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('read')");
		assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation)));
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
