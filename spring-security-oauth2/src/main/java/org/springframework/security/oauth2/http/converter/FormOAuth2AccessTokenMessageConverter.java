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
package org.springframework.security.oauth2.http.converter;

import java.io.IOException;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

/**
 * Converter that can handle inbound form data and convert it to an access token. Needed to support external servers,
 * like Facebook that might not send JSON token data.
 * 
 * @author Rob Winch
 * @author Dave Syer
 * 
 */
public class FormOAuth2AccessTokenMessageConverter extends AbstractHttpMessageConverter<OAuth2AccessToken> {

	private final FormHttpMessageConverter delegateMessageConverter;

	public FormOAuth2AccessTokenMessageConverter() {
		super(MediaType.APPLICATION_FORM_URLENCODED, MediaType.TEXT_PLAIN);
		this.delegateMessageConverter = new FormHttpMessageConverter();
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2AccessToken.class.equals(clazz);
	}

	@Override
	protected OAuth2AccessToken readInternal(Class<? extends OAuth2AccessToken> clazz, HttpInputMessage inputMessage)
			throws IOException, HttpMessageNotReadableException {
		MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
		return DefaultOAuth2AccessToken.valueOf(data.toSingleValueMap());
	}

	@Override
	protected void writeInternal(OAuth2AccessToken accessToken, HttpOutputMessage outputMessage) throws IOException,
			HttpMessageNotWritableException {
		throw new UnsupportedOperationException(
				"This converter is only used for converting from externally aqcuired form data");
	}
}
