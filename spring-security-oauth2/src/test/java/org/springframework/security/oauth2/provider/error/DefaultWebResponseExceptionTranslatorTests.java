/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.provider.error;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import static org.junit.Assert.assertEquals;

/**
 * @author Joe Grandja
 */
public class DefaultWebResponseExceptionTranslatorTests {
	private WebResponseExceptionTranslator translator = new DefaultWebResponseExceptionTranslator();

	// gh-1200
	@Test
	public void translateWhenGeneralExceptionThenReturnInternalServerError() throws Exception {
		String errorMessage = "An error message that contains sensitive information that should not be exposed to the caller.";
		ResponseEntity<OAuth2Exception> response = this.translator.translate(new Exception(errorMessage));
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(), response.getBody().getMessage());
	}
}
