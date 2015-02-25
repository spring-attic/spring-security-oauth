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

package sparklr.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 *
 */
public abstract class AbstractProtectedResourceTests extends AbstractIntegrationTests {

	@Test
	public void testHomePageIsProtected() throws Exception {
		ResponseEntity<String> response = http.getForString("/");
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		assertTrue("Wrong header: " + response.getHeaders(), response.getHeaders().getFirst("WWW-Authenticate")
				.startsWith("Bearer realm="));
	}

	@Test
	public void testBeansResourceIsProtected() throws Exception {
		ResponseEntity<String> response = http.getForString("/admin/beans");
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		assertTrue("Wrong header: " + response.getHeaders(), response.getHeaders().getFirst("WWW-Authenticate")
				.startsWith("Bearer realm="));
	}

	@Test
	public void testHealthResourceIsSecure() throws Exception {
		// In Spring Boot 1.2 the /health endpoint is not open by default, but does allow
		// anonymous access. When we add the OAuth2 layer we don't know about Boot
		// endpoints, so the default has to be a 401.
		assertEquals(HttpStatus.UNAUTHORIZED, http.getStatusCode("/admin/health"));
	}


}
