package org.springframework.security.oauth.consumer.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RunWith(MockitoJUnitRunner.class)
public class OAuthRestTemplateTest {

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
        assertThat(((OAuthClientHttpRequestFactory) restTemplate.getRequestFactory()).getAdditionalOAuthParameters(), is(nullValue()));
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
        assertThat(((OAuthClientHttpRequestFactory) restTemplate.getRequestFactory()).getAdditionalOAuthParameters(), hasEntry(OAuthConsumerParameter.oauth_token.toString(), ""));
        assertThat(restTemplate.postForObject(url, "foo", String.class), is(equalTo("{}")));
    }

    private RequestMatcher headerContains(String name, String substring) {
        return header(name, containsString(substring));
    }

    private RequestMatcher headerDoesNotContain(String name, String substring) {
        return header(name, not(containsString(substring)));
    }

}