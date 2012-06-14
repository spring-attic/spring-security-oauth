/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
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
