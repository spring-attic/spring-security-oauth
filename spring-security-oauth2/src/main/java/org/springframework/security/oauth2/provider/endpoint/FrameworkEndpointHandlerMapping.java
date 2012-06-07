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

package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * A handler mapping for framework endpoints (those annotated with &#64;FrameworkEndpoint).
 * 
 * @author Dave Syer
 * 
 */
public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {

	public FrameworkEndpointHandlerMapping() {
		// Make sure user-supplied mappings take precedence by default (except the resource mapping)
		setOrder(Ordered.LOWEST_PRECEDENCE - 1);
	}

	/**
	 * Detects &#64;FrameworkEndpoint annotations in handler beans.
	 * 
	 * @see org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping#isHandler(java.lang.Class)
	 */
	@Override
	protected boolean isHandler(Class<?> beanType) {
		return AnnotationUtils.findAnnotation(beanType, FrameworkEndpoint.class) != null;
	}

}
