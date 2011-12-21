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

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.MarshalException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.UnmarshalException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Result;
import javax.xml.transform.Source;

import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.xml.AbstractXmlHttpMessageConverter;

/**
 * @author Rob Winch
 *
 * @param <I>
 * @param <E>
 */
abstract class AbstractJaxbMessageConverter<I, E> extends AbstractXmlHttpMessageConverter<E> {

	private final Class<I> internalClass;

	private final Class<E> externalClass;

	private final Unmarshaller unmarshaller;

	private final Marshaller marshaller;

	public AbstractJaxbMessageConverter(Class<I> internalClass, Class<E> externalClass) {
		this.internalClass = internalClass;
		this.externalClass = externalClass;
		try {
			JAXBContext context = JAXBContext.newInstance(this.internalClass);
			this.unmarshaller = context.createUnmarshaller();
			this.marshaller = context.createMarshaller();
			this.marshaller.setProperty("jaxb.fragment", Boolean.TRUE);
		}
		catch (JAXBException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected final E readFromSource(Class<? extends E> clazz, HttpHeaders headers, Source source) throws IOException {
		try {
			JAXBElement<? extends I> jaxbElement = unmarshaller.unmarshal(source, internalClass);
			return convertToExternal(jaxbElement.getValue());
		}
		catch (UnmarshalException ex) {
			throw new HttpMessageNotReadableException("Could not unmarshal to [" + clazz + "]: " + ex.getMessage(), ex);
		}
		catch (JAXBException ex) {
			throw new HttpMessageConversionException("Could not instantiate JAXBContext: " + ex.getMessage(), ex);
		}
	}

	@Override
	protected final void writeToResult(E accessToken, HttpHeaders headers, Result result) throws IOException {
		I convertedAccessToken = convertToInternal(accessToken);
		try {
			marshaller.marshal(convertedAccessToken, result);
		}
		catch (MarshalException ex) {
			throw new HttpMessageNotWritableException("Could not marshal [" + accessToken + "]: " + ex.getMessage(), ex);
		}
		catch (JAXBException ex) {
			throw new HttpMessageConversionException("Could not instantiate JAXBContext: " + ex.getMessage(), ex);
		}
	}

	@Override
	protected final boolean supports(Class<?> clazz) {
		return this.externalClass.isAssignableFrom(clazz);
	}

	protected abstract E convertToExternal(I internalValue);

	protected abstract I convertToInternal(E externalValue);
}
