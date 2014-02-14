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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.junit.Test;

/**
 * @author Ryan Heaton
 */
public class RSA_SHA1SignatureMethodTests {

	/**
	 * tests signing and verifying.
	 */
	@Test
	public void testSignAndVerify() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();
		String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";

		byte[] signatureBytes;
		{
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(keyPair.getPrivate());
			signer.update(baseString.getBytes("UTF-8"));
			signatureBytes = signer.sign();
		}

		{
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(keyPair.getPublic());
			signer.update(baseString.getBytes("UTF-8"));
			assertTrue(signer.verify(signatureBytes));
		}

		RSA_SHA1SignatureMethod signatureMethod = new RSA_SHA1SignatureMethod(keyPair.getPrivate(), keyPair.getPublic());
		String signature = signatureMethod.sign(baseString);
		signatureMethod.verify(baseString, signature);
	}

	/**
	 * tests how to instantiate a public key from text.
	 */
	@Test
	public void testInstantiatePublicKey() throws Exception {
		String googleOAuthCert = "-----BEGIN CERTIFICATE-----\n"
				+ "MIIDBDCCAm2gAwIBAgIJAK8dGINfkSTHMA0GCSqGSIb3DQEBBQUAMGAxCzAJBgNV\n"
				+ "BAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzETMBEG\n"
				+ "A1UEChMKR29vZ2xlIEluYzEXMBUGA1UEAxMOd3d3Lmdvb2dsZS5jb20wHhcNMDgx\n"
				+ "MDA4MDEwODMyWhcNMDkxMDA4MDEwODMyWjBgMQswCQYDVQQGEwJVUzELMAkGA1UE\n"
				+ "CBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBJ\n"
				+ "bmMxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
				+ "ADCBiQKBgQDQUV7ukIfIixbokHONGMW9+ed0E9X4m99I8upPQp3iAtqIvWs7XCbA\n"
				+ "bGqzQH1qX9Y00hrQ5RRQj8OI3tRiQs/KfzGWOdvLpIk5oXpdT58tg4FlYh5fbhIo\n"
				+ "VoVn4GvtSjKmJFsoM8NRtEJHL1aWd++dXzkQjEsNcBXwQvfDb0YnbQIDAQABo4HF\n"
				+ "MIHCMB0GA1UdDgQWBBSm/h1pNY91bNfW08ac9riYzs3cxzCBkgYDVR0jBIGKMIGH\n"
				+ "gBSm/h1pNY91bNfW08ac9riYzs3cx6FkpGIwYDELMAkGA1UEBhMCVVMxCzAJBgNV\n"
				+ "BAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUg\n"
				+ "SW5jMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbYIJAK8dGINfkSTHMAwGA1UdEwQF\n"
				+ "MAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAYpHTr3vQNsHHHUm4MkYcDB20a5KvcFoX\n"
				+ "gCcYtmdyd8rh/FKeZm2me7eQCXgBfJqQ4dvVLJ4LgIQiU3R5ZDe0WbW7rJ3M9ADQ\n"
				+ "FyQoRJP8OIMYW3BoMi0Z4E730KSLRh6kfLq4rK6vw7lkH9oynaHHWZSJLDAp17cP\n" + "j+6znWkN9/g=\n"
				+ "-----END CERTIFICATE-----";
		Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(
				new ByteArrayInputStream(googleOAuthCert.getBytes("utf-8")));
		RSAKeySecret secret = new RSAKeySecret(cert.getPublicKey());
		assertNotNull(secret);
	}

}
