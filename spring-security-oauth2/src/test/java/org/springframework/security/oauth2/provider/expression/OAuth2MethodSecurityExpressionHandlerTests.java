/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.expression;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Collections;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
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
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.util.ReflectionUtils;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Dave Syer
 * @author Radek Ostrowski
 */
class OAuth2MethodSecurityExpressionHandlerTests {

    private OAuth2MethodSecurityExpressionHandler handler = new OAuth2MethodSecurityExpressionHandler();

    @Test
    void testScopesWithOr() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "bar", "", "client_credentials", "ROLE_CLIENT"));
        request.setApproved(true);
        OAuth2Request clientAuthentication = request.createOAuth2Request();
        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass", AuthorityUtils.createAuthorityList("ROLE_USER"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('write') or #oauth2.isUser()");
        assertTrue((Boolean) expression.getValue(context));
    }

    @Test
    void testScopesInsufficient() throws Exception {
        assertThrows(AccessDeniedException.class, () -> {
            AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
            request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "bar", "", "client_credentials", "ROLE_CLIENT"));
            OAuth2Request clientAuthentication = request.createOAuth2Request();
            Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass", AuthorityUtils.createAuthorityList("ROLE_USER"));
            OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
            MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
            EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
            Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('write')");
            expression.getValue(context);
        });
    }

    @Test
    void testOauthClient() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new BaseClientDetails("foo", "", "", "client_credentials", "ROLE_CLIENT"));
        Authentication userAuthentication = null;
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(), request.isApproved(), request.getScope(), request.getResourceIds(), request.getRedirectUri(), request.getResponseTypes(), request.getExtensions());
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole('ROLE_CLIENT')");
        assertTrue((Boolean) expression.getValue(context));
    }

    @Test
    void testScopes() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('read','write')");
        assertTrue((Boolean) expression.getValue(context));
    }

    @Test
    void testScopesRegex() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("ns_admin:read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasScopeMatching('.*_admin:read')");
        assertTrue((Boolean) expression.getValue(context));
        expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScopeMatching('.*_admin:write','.*_admin:read')");
        assertTrue((Boolean) expression.getValue(context));
    }

    @Test
    void testScopesRegexThrowsException() throws Exception {
        assertThrows(AccessDeniedException.class, () -> {
            OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("ns_admin:read"));
            Authentication userAuthentication = null;
            OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
            MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testOauthClient"));
            EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
            Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasScopeMatching('.*_admin:write')");
            assertFalse((Boolean) expression.getValue(context));
        });
    }

    @Test
    void testNonOauthClient() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testNonOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole()");
        assertFalse((Boolean) expression.getValue(context));
    }

    @Test
    void testStandardSecurityRoot() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", null);
        assertTrue(clientAuthentication.isAuthenticated());
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testStandardSecurityRoot"));
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("isAuthenticated()");
        assertTrue((Boolean) expression.getValue(context));
    }

    @Test
    void testReEvaluationWithDifferentRoot() throws Exception {
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.isClient()");
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(), "testNonOauthClient"));
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        assertFalse((Boolean) expression.getValue(context));
        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(storedOAuth2Request, null);
        EvaluationContext anotherContext = handler.createEvaluationContext(oAuth2Authentication, invocation);
        assertTrue((Boolean) expression.getValue(anotherContext));
    }
}
