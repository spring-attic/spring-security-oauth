package org.springframework.security.oauth2.common;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests serialization of an {@link org.springframework.security.oauth2.common.OAuth2AccessToken} using jackson.
 *
 * @author Rob Winch
 */
@PrepareForTest(OAuth2AccessTokenJackson2Serializer.class)
class OAuth2AccessTokenJackson2SerializerTests extends BaseOAuth2AccessTokenJacksonTest {

    protected ObjectMapper mapper;

    @BeforeEach
    void createObjectMapper() {
        mapper = new ObjectMapper();
    }

    @Test
    void writeValueAsStringNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOREFRESH, encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithEmptyScope() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().clear();
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_SINGLESCOPE, encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithNullScope() throws JsonGenerationException, JsonMappingException, IOException {
        thrown.expect(JsonMappingException.class);
        thrown.expectMessage("Scopes cannot be null or empty. Got [null]");
        accessToken.getScope().clear();
        try {
            accessToken.getScope().add(null);
        } catch (NullPointerException e) {
            // short circuit NPE from Java 7 (which is correct but only relevant for this test)
            throw new JsonMappingException("Scopes cannot be null or empty. Got [null]");
        }
        mapper.writeValueAsString(accessToken);
    }

    @Test
    void writeValueAsStringWithEmptyStringScope() throws JsonGenerationException, JsonMappingException, IOException {
        thrown.expect(JsonMappingException.class);
        thrown.expectMessage("Scopes cannot be null or empty. Got []");
        accessToken.getScope().clear();
        accessToken.getScope().add("");
        mapper.writeValueAsString(accessToken);
    }

    @Test
    void writeValueAsStringWithQuoteInScope() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().add("\"");
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\\\" read write\"}", encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithMultiScopes() throws JsonGenerationException, JsonMappingException, IOException {
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(ACCESS_TOKEN_MULTISCOPE, encodedAccessToken);
    }

    @Test
    void writeValueAsStringWithMac() throws Exception {
        accessToken.setTokenType("mac");
        String expectedEncodedAccessToken = ACCESS_TOKEN_MULTISCOPE.replace("bearer", accessToken.getTokenType());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(expectedEncodedAccessToken, encodedAccessToken);
    }

    @Test
    void writeValueWithAdditionalInformation() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        accessToken.setExpiration(null);
        accessToken.setAdditionalInformation(additionalInformation);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_ADDITIONAL_INFO, encodedAccessToken);
    }
}
