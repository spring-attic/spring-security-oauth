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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.stereotype.Component;

/**
 * <p>Synonym for &#64;Controller but only used for endpoints provided by the framework (so it never clashes with user's
 * own endpoints defined with &#64;Controller). Use with &#64;RequestMapping and all the other &#64;Controller features
 * (and match with a {@link FrameworkEndpointHandlerMapping} in the servlet context).</p>
 * 
 * <p>
 * Users of the Spring Security OAuth2 XSD namespace need not use this feature explicitly as the relevant handlers will
 * be registered by the parsers.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
@Component
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FrameworkEndpoint {

}
