/*
 * Copyright 2006-2018 the original author or authors.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTR_NAME;
import static org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Dave Syer
 */
class AuthorizationEndpointTests {

    private AuthorizationEndpoint endpoint = new AuthorizationEndpoint();

    private HashMap<String, Object> model = new HashMap<String, Object>();

    private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();

    private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    private BaseClientDetails client;

    private AuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state, String scope, Set<String> responseTypes) {
        HashMap<String, String> parameters = new HashMap<String, String>();
        parameters.put(OAuth2Utils.CLIENT_ID, clientId);
        if (redirectUri != null) {
            parameters.put(OAuth2Utils.REDIRECT_URI, redirectUri);
        }
        if (state != null) {
            parameters.put(OAuth2Utils.STATE, state);
        }
        if (scope != null) {
            parameters.put(OAuth2Utils.SCOPE, scope);
        }
        if (responseTypes != null) {
            parameters.put(OAuth2Utils.RESPONSE_TYPE, OAuth2Utils.formatParameterList(responseTypes));
        }
        return new AuthorizationRequest(parameters, Collections.<String, String>emptyMap(), parameters.get(OAuth2Utils.CLIENT_ID), OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)), null, null, false, parameters.get(OAuth2Utils.STATE), parameters.get(OAuth2Utils.REDIRECT_URI), OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.RESPONSE_TYPE)));
    }

    @BeforeEach
    void init() throws Exception {
        client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("https://anywhere.com"));
        client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "implicit"));
        endpoint.setClientDetailsService(new ClientDetailsService() {

            public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
                return client;
            }
        });
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                return null;
            }
        });
        endpoint.setRedirectResolver(new DefaultRedirectResolver());
        endpoint.afterPropertiesSet();
    }

    @Test
    void testMandatoryProperties() throws Exception {
        assertThrows(IllegalStateException.class, () -> {
            endpoint = new AuthorizationEndpoint();
            endpoint.afterPropertiesSet();
        });
    }

    @Test
    void testStartAuthorizationCodeFlow() throws Exception {
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
        assertEquals("forward:/oauth/confirm_access", result.getViewName());
    }

    @Test
    void testApprovalStoreAddsScopes() throws Exception {
        ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
        userApprovalHandler.setApprovalStore(new InMemoryApprovalStore());
        endpoint.setUserApprovalHandler(userApprovalHandler);
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
        assertEquals("forward:/oauth/confirm_access", result.getViewName());
        assertTrue(result.getModel().containsKey("scopes"));
    }

    @Test
    void testStartAuthorizationCodeFlowForClientCredentialsFails() throws Exception {
        assertThrows(OAuth2Exception.class, () -> {
            client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
            ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", null, null, null, Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
            assertEquals("forward:/oauth/confirm_access", result.getViewName());
        });
    }

    @Test
    void testAuthorizationCodeWithFragment() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com#bar", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere.com?code=thecode#bar", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeWithQueryParams() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com?foo=bar", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere.com?foo=bar&code=thecode", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeWithTrickyState() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com", " =?s", null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere.com?code=thecode&state=%20%3D?s", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeWithMultipleQueryParams() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com?foo=bar&bar=foo", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere.com?foo=bar&bar=foo&code=thecode", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeWithTrickyQueryParams() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com?foo=b =&bar=f $", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        String url = ((RedirectView) result).getUrl();
        assertEquals("https://anywhere.com?foo=b%20=&bar=f%20$&code=thecode", url);
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(url).build().getQueryParams();
        assertEquals("[b%20=]", params.get("foo").toString());
        assertEquals("[f%20$]", params.get("bar").toString());
    }

    @Test
    void testAuthorizationCodeWithTrickyEncodedQueryParams() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com/path?foo=b%20%3D&bar=f%20$", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere.com/path?foo=b%20%3D&bar=f%20$&code=thecode", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeWithMoreTrickyEncodedQueryParams() throws Exception {
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere?t=a%3Db%26ep%3Dtest%2540test.me", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model, sessionStatus, principal);
        assertEquals("https://anywhere?t=a%3Db%26ep%3Dtest%2540test.me&code=thecode", ((RedirectView) result).getUrl());
    }

    @Test
    void testAuthorizationCodeError() throws Exception {
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices() {

            @Override
            public String createAuthorizationCode(OAuth2Authentication authentication) {
                throw new InvalidScopeException("FOO");
            }
        });
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.startsWith("https://anywhere.com"), "Wrong view: " + result);
        assertTrue(url.contains("?error="), "No error: " + result);
        assertTrue(url.contains("&state=mystate"), "Wrong state: " + result);
    }

    @Test
    void testAuthorizationCodeWithMultipleResponseTypes() throws Exception {
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");
        responseTypes.add("other");
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", null, null, "read", responseTypes).getRequestParameters(), sessionStatus, principal);
        assertEquals("forward:/oauth/confirm_access", result.getViewName());
    }

    @Test
    void testImplicitPreApproved() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
                token.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
                return token;
            }
        });
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.startsWith("https://anywhere.com"), "Wrong view: " + result);
        assertTrue(url.contains("&state=mystate"), "Wrong state: " + result);
        assertTrue(url.contains("access_token="), "Wrong token: " + result);
        assertTrue(url.contains("foo=bar"), "Wrong token: " + result);
    }

    @Test
    void testImplicitAppendsScope() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
                token.setScope(Collections.singleton("read"));
                return token;
            }
        });
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.contains("&scope=read"), "Wrong scope: " + result);
    }

    @Test
    void testImplicitWithQueryParam() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
                return token;
            }
        });
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com?foo=bar", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.contains("foo=bar"), "Wrong url: " + result);
    }

    @Test
    void testImplicitWithAdditionalInfo() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
                token.setAdditionalInformation(Collections.<String, Object>singletonMap("foo", "bar"));
                return token;
            }
        });
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.contains("foo=bar"), "Wrong url: " + result);
    }

    @Test
    void testImplicitAppendsScopeWhenDefaulting() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
                token.setScope(new LinkedHashSet<String>(Arrays.asList("read", "write")));
                return token;
            }
        });
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }

            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }
        });
        client.setScope(Collections.singleton("read"));
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", null, Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.contains("&scope=read%20write"), "Wrong scope: " + result);
    }

    @Test
    void testImplicitPreApprovedButInvalid() throws Exception {
        assertThrows(InvalidScopeException.class, () -> {
            endpoint.setTokenGranter(new TokenGranter() {

                public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                    throw new IllegalStateException("Shouldn't be called");
                }
            });
            endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

                public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                    return true;
                }

                public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                    return authorizationRequest;
                }

                public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                    return authorizationRequest;
                }
            });
            client.setScope(Collections.singleton("smallscope"));
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "bigscope", Collections.singleton("token"));
            ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
            String url = ((RedirectView) result.getView()).getUrl();
            assertTrue(url.startsWith("https://anywhere.com"), "Wrong view: " + result);
        });
    }

    @Test
    void testImplicitUnapproved() throws Exception {
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                return null;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        assertEquals("forward:/oauth/confirm_access", result.getViewName());
    }

    @Test
    void testImplicitError() throws Exception {
        endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {

            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return authorizationRequest;
            }

            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
                return true;
            }
        });
        endpoint.setTokenGranter(new TokenGranter() {

            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                return null;
            }
        });
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "mystate", "myscope", Collections.singleton("token"));
        ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
        String url = ((RedirectView) result.getView()).getUrl();
        assertTrue(url.startsWith("https://anywhere.com"), "Wrong view: " + result);
        assertTrue(url.contains("#error="), "No error: " + result);
        assertTrue(url.contains("&state=mystate"), "Wrong state: " + result);
    }

    @Test
    void testApproveOrDeny() throws Exception {
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com", null, null, Collections.singleton("code"));
        request.setApproved(true);
        Map<String, String> approvalParameters = new HashMap<String, String>();
        approvalParameters.put("user_oauth_approval", "true");
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        View result = endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        assertTrue(((RedirectView) result).getUrl().startsWith("https://anywhere.com"), "Wrong view: " + result);
    }

    @Test
    void testApprovalDenied() throws Exception {
        AuthorizationRequest request = getAuthorizationRequest("foo", "https://anywhere.com", null, null, Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
        Map<String, String> approvalParameters = new HashMap<String, String>();
        approvalParameters.put("user_oauth_approval", "false");
        View result = endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        String url = ((RedirectView) result).getUrl();
        assertTrue(url.startsWith("https://anywhere.com"), "Wrong view: " + result);
        assertTrue(url.contains("error=access_denied"), "Wrong view: " + result);
    }

    @Test
    void testDirectApproval() throws Exception {
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", "https://anywhere.com", null, "read", Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
        // Should go to approval page (SECOAUTH-191)
        assertFalse(result.getView() instanceof RedirectView);
    }

    @Test
    void testRedirectUriOptionalForAuthorization() throws Exception {
        ModelAndView result = endpoint.authorize(model, getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
        // RedirectUri parameter should be null (SECOAUTH-333), however the resolvedRedirectUri not
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) result.getModelMap().get(AUTHORIZATION_REQUEST_ATTR_NAME);
        assertNull(authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI));
        assertEquals("https://anywhere.com", authorizationRequest.getRedirectUri());
    }

    /**
     * Ensure that if the approval endpoint is called without a resolved redirect URI, the request fails.
     * @throws Exception
     */
    @Test
    void testApproveOrDenyWithOAuth2RequestWithoutRedirectUri() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest request = getAuthorizationRequest("foo", null, null, null, Collections.singleton("code"));
            request.setApproved(true);
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, request);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(request));
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedClientId() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setClientId("bar");
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedState() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setState("state-5678");
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedRedirectUri() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setRedirectUri("https://somewhere.com");
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedResponseTypes() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setResponseTypes(Collections.singleton("implicit"));
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedScope() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setScope(Arrays.asList("read", "write"));
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedApproved() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            authorizationRequest.setApproved(false);
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setApproved(true);
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedResourceIds() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setResourceIds(Collections.singleton("resource-other"));
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    @Test
    void testApproveWithModifiedAuthorities() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
            model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
            model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, endpoint.unmodifiableMap(authorizationRequest));
            // Modify authorization request
            authorizationRequest.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("authority-other"));
            Map<String, String> approvalParameters = new HashMap<String, String>();
            approvalParameters.put("user_oauth_approval", "true");
            endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        });
    }

    private class StubAuthorizationCodeServices implements AuthorizationCodeServices {

        private OAuth2Authentication authentication;

        public String createAuthorizationCode(OAuth2Authentication authentication) {
            this.authentication = authentication;
            return "thecode";
        }

        public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
            return authentication;
        }
    }
}
