/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Dave Syer
 *
 */
public class SpelViewTests {

	private SpelView view;

	private MockHttpServletResponse response = new MockHttpServletResponse();
	private MockHttpServletRequest request = new MockHttpServletRequest();

	@Test
	public void sunnyDay() throws Exception {
		view = new SpelView("${hit}");
		view.render(Collections.singletonMap("hit", "Ouch"), request, response);
		assertEquals("Ouch", response.getContentAsString());
	}

	@Test
	public void nonRecursive() throws Exception {
		view = new SpelView("${hit}");
		view.render(Collections.singletonMap("hit", "${ouch}"), request, response);
		// Expressions embedded in resolved values do not resolve recursively
		assertEquals("${ouch}", response.getContentAsString());
	}

	@Test
	public void recursive() throws Exception {
		// Recursive expressions in the template resolve
		view = new SpelView("${${hit}}");
		Map<String,Object> map = new HashMap<String, Object>();
		map.put("hit", "me");
		map.put("me", "${ouch}");
		view.render(map, request, response);
		// But expressions embedded in resolved values do not
		assertEquals("${ouch}", response.getContentAsString());
	}

}
