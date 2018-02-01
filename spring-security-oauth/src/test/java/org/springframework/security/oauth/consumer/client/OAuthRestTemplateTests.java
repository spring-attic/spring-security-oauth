package org.springframework.security.oauth.consumer.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RunWith(MockitoJUnitRunner.class)
public class OAuthRestTemplateTests {

    @Mock
    private ProtectedResourceDetails details;

    @Test
    public void testOAuthRestTemplateNoAdditionalParameters() {
        String url = "http://myhost.com/resource?with=some&query=params&too";

        when(details.getSignatureMethod()).thenReturn("HMAC-SHA1");
        when(details.getConsumerKey()).thenReturn("consumerKey");
        when(details.getSharedSecret()).thenReturn(new SharedConsumerSecretImpl("consumerSecret"));
        when(details.getAuthorizationHeaderRealm()).thenReturn("realm");
        when(details.isAcceptsAuthorizationHeader()).thenReturn(true);
        when(details.getAdditionalRequestHeaders()).thenReturn(null);
        when(details.getAdditionalParameters()).thenReturn(null);

        OAuthRestTemplate restTemplate = new OAuthRestTemplate(details);

        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);
        mockServer
                .expect(requestTo(url))
                .andExpect(method(POST))
                .andExpect(headerContains("Authorization", "OAuth realm=\"realm\""))
                .andExpect(headerContains("Authorization", "oauth_consumer_key=\"consumerKey\""))
                .andExpect(headerDoesNotContain("Authorization", "oauth_token"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        assertThat(restTemplate.getRequestFactory(), is(instanceOf(OAuthClientHttpRequestFactory.class)));
        assertTrue(((OAuthClientHttpRequestFactory) restTemplate.getRequestFactory()).getAdditionalOAuthParameters().isEmpty());
        assertThat(restTemplate.postForObject(url, "foo", String.class), is(equalTo("{}")));
    }

    @Test
    public void testOAuthRestTemplateWithAdditionalParameters() {
        String url = "http://myhost.com/resource?with=some&query=params&too";

        when(details.getSignatureMethod()).thenReturn("HMAC-SHA1");
        when(details.getConsumerKey()).thenReturn("consumerKey");
        when(details.getSharedSecret()).thenReturn(new SharedConsumerSecretImpl("consumerSecret"));
        when(details.getAuthorizationHeaderRealm()).thenReturn("realm");
        when(details.isAcceptsAuthorizationHeader()).thenReturn(true);
        when(details.getAdditionalRequestHeaders()).thenReturn(null);
        when(details.getAdditionalParameters()).thenReturn(Collections.singletonMap("oauth_token", ""));

        OAuthRestTemplate restTemplate = new OAuthRestTemplate(details);

        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);
        mockServer
                .expect(requestTo(url))
                .andExpect(method(POST))
                .andExpect(headerContains("Authorization", "OAuth realm=\"realm\""))
                .andExpect(headerContains("Authorization", "oauth_consumer_key=\"consumerKey\""))
                .andExpect(headerContains("Authorization", "oauth_token=\"\""))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        assertThat(restTemplate.getRequestFactory(), is(instanceOf(OAuthClientHttpRequestFactory.class)));
        Map<String, String> additionalOAuthParameters = ((OAuthClientHttpRequestFactory) restTemplate.getRequestFactory()).getAdditionalOAuthParameters();
        assertTrue(additionalOAuthParameters.containsKey("oauth_token"));
        assertTrue(additionalOAuthParameters.get("oauth_token").isEmpty());
        assertThat(restTemplate.postForObject(url, "foo", String.class), is(equalTo("{}")));
    }

    private RequestMatcher headerContains(String name, String substring) {
        return header(name, containsString(substring));
    }

    private RequestMatcher headerDoesNotContain(String name, String substring) {
        return header(name, not(containsString(substring)));
    }

}