package org.springframework.security.oauth2.provider.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

/**
 * @author Michał Drożdż
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenExtractorTest {

    private BearerTokenExtractor bearerTokenExtractor = new BearerTokenExtractor();

    @Mock
    private HttpServletRequest request;

    @Test
    public void extractHeaderToken_noAuthorizationHeadersToken(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.<String>emptyEnumeration());

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertNull(result);
    }

    @Test
    public void extractHeaderToken_noBearerToken(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Collections.singleton("Basic auth")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertNull(result);
    }

    @Test
    public void extractHeaderToken_oneBearerToken(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Collections.singleton("Bearer auth")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertThat(result, is("auth"));
    }

    @Test
    public void extractHeaderToken_multipleBearerTokens(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer auth", "Bearer auth2")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertThat(result, is("auth"));
    }

    @Test
    public void extractHeaderToken_multipleTokenTypes(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Basic auth", "Bearer auth2")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertThat(result, is("auth2"));
    }

    @Test
    public void extractHeaderToken_multipleTokenTypesInOneHeaderBasicFirst(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Basic auth, Bearer auth2")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertThat(result, is(nullValue()));
    }

    @Test
    public void extractHeaderToken_multipleTokenTypesInOneHeaderBearerFirst(){
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer auth2, Basic auth")));

        String result = bearerTokenExtractor.extractHeaderToken(request);

        assertThat(result, is("auth2"));
    }
}
