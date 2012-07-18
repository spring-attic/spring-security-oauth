/*
 * Copyright 2006-2011 the original author or authors.
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


package org.springframework.security.oauth.examples.tonr.converter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.GenericConverter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;

/**
 * @author Dave Syer
 * 
 */
public class AccessTokenRequestConverter implements GenericConverter {

	private Set<ConvertiblePair> convertibleTypes = new HashSet<GenericConverter.ConvertiblePair>(
			Arrays.asList(new ConvertiblePair(AccessTokenRequest.class, AccessTokenRequest.class)));

	public Set<ConvertiblePair> getConvertibleTypes() {
		return convertibleTypes;
	}

	public Object convert(Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
		return source;
	}

}
