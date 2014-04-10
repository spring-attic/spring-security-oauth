/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class FrameworkEndpointHandlerMappingTests {
	
	private FrameworkEndpointHandlerMapping mapping = new FrameworkEndpointHandlerMapping();
	
	@Test
	public void defaults() throws Exception {
		assertEquals("/oauth/token", mapping.getPath("/oauth/token"));
		assertEquals("/oauth/authorize", mapping.getPath("/oauth/authorize"));
		assertEquals("/oauth/error", mapping.getPath("/oauth/error"));
		assertEquals("/oauth/confirm_access", mapping.getPath("/oauth/confirm_access"));
	}

	@Test
	public void mappings() throws Exception {
		mapping.setMappings(Collections.singletonMap("/oauth/token", "/token"));
		assertEquals("/token", mapping.getPath("/oauth/token"));
	}

	@Test
	public void forward() throws Exception {
		mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "forward:/approve"));
		assertEquals("/approve", mapping.getPath("/oauth/confirm_access"));
	}

	@Test
	public void redirect() throws Exception {
		mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "redirect:/approve"));
		assertEquals("/approve", mapping.getPath("/oauth/confirm_access"));
	}

}
