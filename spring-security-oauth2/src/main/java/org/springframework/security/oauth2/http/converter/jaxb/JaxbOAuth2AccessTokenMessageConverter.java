/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.http.converter.jaxb;

import java.util.Date;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;

public final class JaxbOAuth2AccessTokenMessageConverter extends AbstractJaxbMessageConverter<JaxbOAuth2AccessToken,OAuth2AccessToken> {

	public JaxbOAuth2AccessTokenMessageConverter() {
		super(JaxbOAuth2AccessToken.class,OAuth2AccessToken.class);
	}

	protected JaxbOAuth2AccessToken convertToInternal(OAuth2AccessToken accessToken) {
		JaxbOAuth2AccessToken jaxbAccessToken = new JaxbOAuth2AccessToken();
		jaxbAccessToken.setAccessToken(accessToken.getValue());
		jaxbAccessToken.setExpriation(accessToken.getExpiration());
		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		if(refreshToken != null) {
			jaxbAccessToken.setRefreshToken(refreshToken.getValue());
		}
		return jaxbAccessToken;
	}

	protected OAuth2AccessToken convertToExternal(JaxbOAuth2AccessToken jaxbAccessToken) {
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(jaxbAccessToken.getAccessToken());
		String refreshToken = jaxbAccessToken.getRefreshToken();
		if(refreshToken != null) {
			accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
		}
		Date expiration = jaxbAccessToken.getExpiration();
		if(expiration != null) {
			accessToken.setExpiration(expiration);
		}
		return accessToken;
	}
}
