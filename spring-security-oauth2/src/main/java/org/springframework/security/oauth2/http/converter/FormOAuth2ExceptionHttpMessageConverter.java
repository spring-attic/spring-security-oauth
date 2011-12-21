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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Converter that can handle inbound form data and convert it to an OAuth2 exception. Needed to support external servers,
 * like Facebook that might not send JSON data.
 * 
@author Rob Winch
 * @author Dave Syer
 *
 */
public final class FormOAuth2ExceptionHttpMessageConverter implements HttpMessageConverter<OAuth2Exception> {

	private static final List<MediaType> SUPPORTED_MEDIA = Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED);

	private final FormHttpMessageConverter delegateMessageConverter = new FormHttpMessageConverter();

	public boolean canRead(Class<?> clazz, MediaType mediaType) {
		return OAuth2Exception.class.equals(clazz) && MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
	}

	public boolean canWrite(Class<?> clazz, MediaType mediaType) {
		return OAuth2Exception.class.equals(clazz) && MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
	}

	public List<MediaType> getSupportedMediaTypes() {
		return SUPPORTED_MEDIA;
	}

	public OAuth2Exception read(Class<? extends OAuth2Exception> clazz, HttpInputMessage inputMessage)
			throws IOException, HttpMessageNotReadableException {
		MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
		Map<String,String> flattenedData = data.toSingleValueMap();
		return OAuth2Exception.valueOf(flattenedData);
	}

	public void write(OAuth2Exception t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException,
			HttpMessageNotWritableException {
		MultiValueMap<String, String> data = new LinkedMultiValueMap<String, String>();
		data.add(OAuth2Exception.ERROR, t.getOAuth2ErrorCode());
		data.add(OAuth2Exception.DESCRIPTION, t.getMessage());
		Map<String, String> additionalInformation = t.getAdditionalInformation();
		if(additionalInformation != null) {
			for(Map.Entry<String,String> entry : additionalInformation.entrySet()) {
				data.add(entry.getKey(), entry.getValue());
			}
		}
		delegateMessageConverter.write(data, contentType, outputMessage);
	}

}
