/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common.signature;

import org.junit.Test;

/**
 * @author Ryan Heaton
 */
public class PlainTextSignatureMethodTests {

	/**
	 * tests signing and verifying.
	 */
	@Test
	public void testSignAndVerify() throws Exception {
		String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";
		PlainTextSignatureMethod signatureMethod = new PlainTextSignatureMethod("shhhhhhhh", null, null);
		String signature = signatureMethod.sign(baseString);
		signatureMethod.verify(baseString, signature);
	}

}