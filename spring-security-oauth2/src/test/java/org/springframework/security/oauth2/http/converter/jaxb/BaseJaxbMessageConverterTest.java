/*
 * Copyright 2011-2012 the original author or authors.
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

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;

import javax.xml.bind.JAXBContext;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;

/**
 *
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(System.class)
abstract class BaseJaxbMessageConverterTest {
	protected static final String OAUTH_ACCESSTOKEN_NOEXPIRES = "<oauth><access_token>SlAV32hkKG</access_token></oauth>";
	protected static final String OAUTH_ACCESSTOKEN_NOREFRESH = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in></oauth>";
	protected static final String OAUTH_ACCESSTOKEN = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in><refresh_token>8xLOxBtZp8</refresh_token></oauth>";
	protected MediaType contentType;
	protected ByteArrayOutputStream output;

	@Mock
	protected Date expiration;
	@Mock
	protected HttpOutputMessage outputMessage;
	@Mock
	protected HttpInputMessage inputMessage;
	@Mock
	protected HttpHeaders headers;
	@Mock
	protected JAXBContext context;

	@Before
	public final void setUp() throws Exception {
		mockStatic(System.class);
		long now = 1323123715041L;
		when(System.currentTimeMillis()).thenReturn(now);
		when(expiration.before(any(Date.class))).thenReturn(false);
		when(expiration.getTime()).thenReturn(now + 10000);

		output = new ByteArrayOutputStream();
		contentType = MediaType.APPLICATION_XML;
		when(headers.getContentType()).thenReturn(contentType);
		when(outputMessage.getHeaders()).thenReturn(headers);
		when(outputMessage.getBody()).thenReturn(output);
	}
	

	protected InputStream createInputStream(String in) throws UnsupportedEncodingException {
		return new ByteArrayInputStream(in.getBytes("UTF-8"));
	}

	protected String getOutput() throws UnsupportedEncodingException {
		return output.toString("UTF-8");
	}
	
	protected void useMockJAXBContext(Object object, Class<?> jaxbClassToBeBound) throws Exception {
		JAXBContext jaxbContext = JAXBContext.newInstance(jaxbClassToBeBound);
		when(context.createMarshaller()).thenReturn(jaxbContext.createMarshaller());
		when(context.createUnmarshaller()).thenReturn(jaxbContext.createUnmarshaller());
		WhiteboxImpl.setInternalState(object, JAXBContext.class, context);
	}
}
