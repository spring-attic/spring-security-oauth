package org.company.oauth2;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

public class CustomOAuth2AccessToken extends DefaultOAuth2AccessToken {

    public CustomOAuth2AccessToken(String value) {
        super(value);
    }
}
