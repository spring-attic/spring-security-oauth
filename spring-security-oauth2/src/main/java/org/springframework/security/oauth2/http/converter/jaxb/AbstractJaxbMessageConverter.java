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
 * <p>
 * Used as a convenience for converting an external object into an Object that can be marshalled using JAXB.
 * </p>
 * <p>
 * Note that the existing {@link AbstractXmlHttpMessageConverter} implementations will not work due to final methods
 * preventing the modification of the {@link Marshaller}.
 * </p>
 * 
 * @author Rob Winch
 * 
 * @param <I> The internal representation of the object that can be safely marshalled/unmarshalled using JAXB.
 * @param <E> The external representation of the object that is exposed externally but cannot be marshalled/unmarshalled using JAXB.
 */
abstract class AbstractJaxbMessageConverter<I, E> extends AbstractXmlHttpMessageConverter<E> {

	private final Class<I> internalClass;

	private final Class<E> externalClass;
	
	private final JAXBContext context;

	public AbstractJaxbMessageConverter(Class<I> internalClass, Class<E> externalClass) {
		this.internalClass = internalClass;
		this.externalClass = externalClass;
		try {
			context = JAXBContext.newInstance(this.internalClass);
		}
		catch (JAXBException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected final E readFromSource(Class<? extends E> clazz, HttpHeaders headers, Source source) throws IOException {
		try {
			JAXBElement<? extends I> jaxbElement = createUnmarshaller().unmarshal(source, internalClass);
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
			createMarshaller().marshal(convertedAccessToken, result);
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
	
	private Unmarshaller createUnmarshaller() throws JAXBException {
		return context.createUnmarshaller();
	}
	
	private Marshaller createMarshaller() throws JAXBException {
		Marshaller marshaller = context.createMarshaller();
		marshaller.setProperty("jaxb.fragment", Boolean.TRUE);
		return marshaller;
	}
}
