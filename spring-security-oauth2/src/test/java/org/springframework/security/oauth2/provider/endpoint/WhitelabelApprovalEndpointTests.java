/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.servlet.ModelAndView;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Dave Syer
 */
class WhitelabelApprovalEndpointTests {

    private WhitelabelApprovalEndpoint endpoint = new WhitelabelApprovalEndpoint();

    private Map<String, String> parameters = new HashMap<String, String>();

    private MockHttpServletRequest request = new MockHttpServletRequest();

    private MockHttpServletResponse response = new MockHttpServletResponse();

    private AuthorizationRequest createFromParameters(Map<String, String> authorizationParameters) {
        AuthorizationRequest request = new AuthorizationRequest(authorizationParameters, Collections.<String, String>emptyMap(), authorizationParameters.get(OAuth2Utils.CLIENT_ID), OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.SCOPE)), null, null, false, authorizationParameters.get(OAuth2Utils.STATE), authorizationParameters.get(OAuth2Utils.REDIRECT_URI), OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE)));
        return request;
    }

    @Test
    void testApprovalPage() throws Exception {
        request.setContextPath("/foo");
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(content.contains("<form"), "Wrong content: " + content);
        assertTrue(content.contains("/foo/oauth/authorize"), "Wrong content: " + content);
        assertTrue(!content.contains("${"), "Wrong content: " + content);
        assertTrue(!content.contains("_csrf"), "Wrong content: " + content);
        assertTrue(!content.contains("%"), "Wrong content: " + content);
    }

    @Test
    void testApprovalPageWithScopes() throws Exception {
        request.setContextPath("/foo");
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        model.put("scopes", Collections.singletonMap("scope.read", "true"));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(content.contains("scope.read"), "Wrong content: " + content);
        assertTrue(content.contains("checked"), "Wrong content: " + content);
        assertTrue(content.contains("/foo/oauth/authorize"), "Wrong content: " + content);
        assertTrue(!content.contains("${"), "Wrong content: " + content);
        assertTrue(!content.contains("_csrf"), "Wrong content: " + content);
        assertTrue(!content.contains("%"), "Wrong content: " + content);
    }

    @Test
    void testApprovalPageWithCsrf() throws Exception {
        request.setContextPath("/foo");
        request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(content.contains("_csrf"), "Wrong content: " + content);
        assertTrue(content.contains("/foo/oauth/authorize"), "Wrong content: " + content);
        assertTrue(!content.contains("${"), "Wrong content: " + content);
    }

    // gh-1340
    @Test
    void testApprovalPageWithSuspectScope() throws Exception {
        request.setContextPath("/foo");
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        String scope = "${T(java.lang.Runtime).getRuntime().exec(\"cd ..\")}";
        String escapedScope = "T(java.lang.Runtime).getRuntime().exec(&quot;cd ..&quot;)";
        model.put("scopes", Collections.singletonMap(scope, "true"));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(!content.contains(scope), "Wrong content: " + content);
        assertTrue(content.contains(escapedScope), "Wrong content: " + content);
    }

    @Test
    void testApprovalPageWithScopesInForm() throws Exception {
        String expectedContent = "<html><body><h1>OAuth Approval</h1><p>Do you authorize \"client\" to access your protected resources?</p>" + "<form id=\"confirmationForm\" name=\"confirmationForm\" action=\"/foo/oauth/authorize\" method=\"post\">" + "<input name=\"user_oauth_approval\" value=\"true\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><ul>" + "<li><div class=\"form-group\">scope.read: <input type=\"radio\" name=\"scope.read\" value=\"true\" checked>Approve</input> " + "<input type=\"radio\" name=\"scope.read\" value=\"false\">Deny</input></div></li></ul><label>" + "<input name=\"authorize\" value=\"Authorize\" type=\"submit\"/></label></form></body></html>";
        request.setContextPath("/foo");
        request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        model.put("scopes", Collections.singletonMap("scope.read", "true"));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(content.equals(expectedContent), "Wrong content: " + content);
    }

    @Test
    void testApprovalPageWithoutScopesInForm() throws Exception {
        String expectedContent = "<html><body><h1>OAuth Approval</h1><p>Do you authorize \"client\" to access your protected resources?</p>" + "<form id=\"confirmationForm\" name=\"confirmationForm\" action=\"/foo/oauth/authorize\" method=\"post\">" + "<input name=\"user_oauth_approval\" value=\"true\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><label>" + "<input name=\"authorize\" value=\"Authorize\" type=\"submit\"/></label></form>" + "<form id=\"denialForm\" name=\"denialForm\" action=\"/foo/oauth/authorize\" method=\"post\">" + "<input name=\"user_oauth_approval\" value=\"false\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><label>" + "<input name=\"deny\" value=\"Deny\" type=\"submit\"/></label></form></body></html>";
        request.setContextPath("/foo");
        request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
        parameters.put("client_id", "client");
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("authorizationRequest", createFromParameters(parameters));
        ModelAndView result = endpoint.getAccessConfirmation(model, request);
        result.getView().render(result.getModel(), request, response);
        String content = response.getContentAsString();
        assertTrue(content.equals(expectedContent), "Wrong content: " + content);
    }
}
