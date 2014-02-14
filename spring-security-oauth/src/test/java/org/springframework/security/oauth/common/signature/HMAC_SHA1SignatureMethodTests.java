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

import static org.junit.Assert.assertEquals;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * @author Ryan Heaton
 */
public class HMAC_SHA1SignatureMethodTests {

	/**
	 * Test sign and verify.
	 */
	@Test
	public void testSignAndVerify() throws Exception {
		SecretKeySpec spec = new SecretKeySpec("thisismysharedsecretkeythatidontwanttoshare".getBytes("UTF-8"),
				HMAC_SHA1SignatureMethod.MAC_NAME);
		HMAC_SHA1SignatureMethod signatureMethod = new HMAC_SHA1SignatureMethod(spec);
		String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";
		String signature = signatureMethod.sign(baseString);
		signatureMethod.verify(baseString, signature);
	}

	/**
	 * Test sign and verify.
	 */
	@Test
	public void testSignAndVerify2() throws Exception {
		SecretKeySpec spec = new SecretKeySpec(
				"SHHHHH%21%21%21%21%21%21%21%21%21%21&4NbaOg40gJhUYHOG2GqvDHZ%2FLMCdRYRx8d%2FZuLWhghw85S3qwMpE44VIMeqdP6RhebURCIQTJSzsz%2F1cjtXFFOixdC1QfZjUVsfd4MsyICo%3D"
						.getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
		HMAC_SHA1SignatureMethod signatureMethod = new HMAC_SHA1SignatureMethod(spec);
		String baseString = "POST&http%3A%2F%2Flocalhost%3A8080%2Fsparklr%2Fphoto%2F1&oauth_consumer_key%3Dtonr-consumer-key%26oauth_nonce%3D9ed2a59a-f254-4271-95e9-678795ac96f5%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1204899002%26oauth_token%3D0592328d-d03d-4737-905d-c2cccadf32ad%26oauth_version%3D1.0";
		String signature = signatureMethod.sign(baseString);
		signatureMethod.verify(baseString, signature);
	}

	/**
	 * Test sign and verify.
	 */
	@Test
	public void testSignAndVerify3() throws Exception {
		SecretKeySpec spec = new SecretKeySpec("xxxxxx&".getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
		HMAC_SHA1SignatureMethod signatureMethod = new HMAC_SHA1SignatureMethod(spec);
		String baseString = "GET&http%3A%2F%2Flocalhost%3A8080%2Fgrailscrowd%2Foauth%2Frequest_token&oauth_consumer_key%3Dtonrconsumerkey%26oauth_nonce%3D1227967049787975000%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1227967049%26oauth_version%3D1.0";
		String signature = "4KaVKEnW6e1a+vwJTpz0VFqIaGU=";
		String otherSignature = signatureMethod.sign(baseString);
		assertEquals(signature, otherSignature);
		signatureMethod.verify(baseString, otherSignature);
	}

}
