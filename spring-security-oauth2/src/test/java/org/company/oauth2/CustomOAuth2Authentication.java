package org.company.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

public class CustomOAuth2Authentication extends OAuth2Authentication {

    public CustomOAuth2Authentication(
            OAuth2Request storedRequest,
            Authentication userAuthentication) {
        super(storedRequest, userAuthentication);
    }
}
