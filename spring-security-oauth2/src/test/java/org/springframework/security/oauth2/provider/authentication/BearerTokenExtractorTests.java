package org.springframework.security.oauth2.provider.authentication;


import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests RFC7230 compliance of BearerTokenExtractor.
 *
 * @author Jan Brennenstuhl
 *
 */
public class BearerTokenExtractorTests {

    private static final String SOME_OAUTH2_TOKEN = "SOME_OAUTH2_TOKEN";
    private final BearerTokenExtractor objectUnderTest = new BearerTokenExtractor();

    @Test
    public void shouldExtractTokenWhenValidBearerTokenAvailable()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + SOME_OAUTH2_TOKEN);

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldExtractTokenWhenMultipleAuthHeadersPresent()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic YXNkZnNhZGZzYWRmOlZLdDVOMVhk");
        request.addHeader("Authorization", "Bearer " + SOME_OAUTH2_TOKEN);

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldExtractTokenWhenMultipleAuthHeaderValuesAvailable()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + SOME_OAUTH2_TOKEN + ", Basic YXNkZnNhZGZzYWRmOlZLdDVOMVhk");

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldExtractTokenAlthoughAuthHeaderValueIncludesSpaces()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "  Bearer   " + SOME_OAUTH2_TOKEN + "  ");

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldExtractTokenWhenBearerNotPrimary()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",  "Basic YXNkZnNhZGZzYWRmOlZLdDVOMVhk, Bearer " + SOME_OAUTH2_TOKEN);

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldExtractTokenWhenBearerMisspelled()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",  "BEAREr " + SOME_OAUTH2_TOKEN);

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertEquals(SOME_OAUTH2_TOKEN, extractedToken);
    }

    @Test
    public void shouldNotExtractTokenWhenAuthHeaderMissing()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertNull(extractedToken);
    }

    @Test
    public void shouldNotExtractTokenWhenBearerTokenMissingPart1()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic YXNkZnNhZGZzYWRmOlZLdDVOMVhk");

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertNull(extractedToken);
    }

    @Test
    public void shouldNotExtractTokenWhenBearerTokenMissingPart2()  {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "");

        final String extractedToken = objectUnderTest.extractHeaderToken(request);
        assertNull(extractedToken);
    }
}
