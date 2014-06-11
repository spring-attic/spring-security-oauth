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

package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import sparklr.common.AbstractProtectedResourceTests;

/**
 * @author Dave Syer
 *
 */
@SpringApplicationConfiguration(classes = Application.class)
public class ProtectedResourceTests extends AbstractProtectedResourceTests {

	@Test
	public void testDumpResourceIsProtected() throws Exception {
		ResponseEntity<String> response = http.getForString("/admin/dump");
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		assertTrue("Wrong header: " + response.getHeaders(), response.getHeaders().getFirst("WWW-Authenticate")
				.startsWith("Basic realm="));
	}

}
