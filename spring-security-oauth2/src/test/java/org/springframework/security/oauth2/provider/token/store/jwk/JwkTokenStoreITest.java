/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.HttpHeaders;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.discovery.ProviderConfiguration;
import org.springframework.security.oauth2.client.discovery.ProviderDiscoveryClient;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.DelegatingJwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.IssuerClaimVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * @author Joe Grandja
 */
public class JwkTokenStoreITest {
	private MockWebServer server;

	@Before
	public void setUp() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
	}

	@After
	public void cleanUp() throws Exception {
		this.server.shutdown();
	}

	// gh-1114 Issuer claim verification
	@Test
	public void readAccessTokenWhenJwtHasValidIssuerClaimThenVerificationSucceeds() throws Exception {
		String issuer = "http://localhost:8180/auth/realms/Demo";

		this.setUpResponses(issuer);

		ProviderDiscoveryClient discoveryClient = new ProviderDiscoveryClient(this.server.url("").toString());
		ProviderConfiguration providerConfiguration = discoveryClient.discover();

		List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers = new ArrayList<JwtClaimsSetVerifier>();
		jwtClaimsSetVerifiers.add(new IssuerClaimVerifier(providerConfiguration.getIssuer()));

		JwkTokenStore jwkTokenStore = new JwkTokenStore(
				providerConfiguration.getJwkSetUri().toString(),
				new DelegatingJwtClaimsSetVerifier(jwtClaimsSetVerifiers));

		// NOTE: The 'iss' claim in this JWT is http://localhost:8180/auth/realms/Demo
		String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfQ2kzLVZmVl9OMFlBRzIyTlFPZ09VcEZCRERjRGVfckp4cHU1Sks3MDJvIn0.eyJqdGkiOiIzOWQxMmU1NC00MjliLTRkZjUtOTM2OS01YWVlOTFkNzAwZjgiLCJleHAiOjE0ODg5MDk1NzMsIm5iZiI6MCwiaWF0IjoxNDg4OTA5MjczLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgxODAvYXV0aC9yZWFsbXMvRGVtbyIsImF1ZCI6ImJvb3QtYXBwIiwic3ViIjoiNGM5NjE5NDQtN2VkZC00ZDZiLTg2MGUtYmJiZGNhODk0MDU4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYm9vdC1hcHAiLCJhdXRoX3RpbWUiOjE0ODg5MDkyNzMsInNlc3Npb25fc3RhdGUiOiJiMjdjMDZlNi02ODgwLTQxZTEtOTM2MS1jZmEzYzY2ZjYyNjAiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIyYjA5NTFiOC1iMjdkLTRlYWMtYjUxOC1kZTQ5OTA5OTY2ZDgiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYm9vdC1hcGkiOnsicm9sZXMiOlsiYm9vdC1hcGktcm9sZSJdfSwiYm9vdC1hcHAiOnsicm9sZXMiOlsiYm9vdC1yb2xlIl19fSwibmFtZSI6IkFsaWNlICIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiIiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUubmV0In0.NfF5rPMabu8gaigUHZnX3gIzNGAxKpmPP206U5keNtexNqsmQEFO4KT2i1JYLwvNVFnRWCa8FmYokAtzeHgLvHk2B8CZXqL6GSMGQ26wPS5RIFTak9HjfHMhodqSIdy4wZTKmEcum_uYTaCdrVRSfWU8l94xAY6OzwElZX5ulkucvgWQnpFs0HB7X54kB07OqpN8L3i1jeQoEV0iJchtxZiEOSipqMNO7cujMqB_6lf9i78URPuyExfeLzAWyDbMWSJBp3zUoS7HakwE_4oC3eVEYTxDtMRL2yl2_8R0C0g2Dc0Qb9aezFxo3-SDNuy9aicDmibEEOpIoetlrIYbNA";

		OAuth2AccessToken accessToken = jwkTokenStore.readAccessToken(jwt);
		assertEquals(issuer, accessToken.getAdditionalInformation().get("iss"));
	}

	// gh-1114 Issuer claim verification
	@Test(expected = InvalidTokenException.class)
	public void readAccessTokenWhenJwtHasInvalidIssuerClaimThenVerificationFails() throws Exception {
		String issuer = "http://localhost:8180/auth/realms/Demo-2";

		this.setUpResponses(issuer);

		ProviderDiscoveryClient discoveryClient = new ProviderDiscoveryClient(this.server.url("").toString());
		ProviderConfiguration providerConfiguration = discoveryClient.discover();

		List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers = new ArrayList<JwtClaimsSetVerifier>();
		jwtClaimsSetVerifiers.add(new IssuerClaimVerifier(providerConfiguration.getIssuer()));

		JwkTokenStore jwkTokenStore = new JwkTokenStore(
				providerConfiguration.getJwkSetUri().toString(),
				new DelegatingJwtClaimsSetVerifier(jwtClaimsSetVerifiers));

		// NOTE: The 'iss' claim in this JWT is http://localhost:8180/auth/realms/Demo
		String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfQ2kzLVZmVl9OMFlBRzIyTlFPZ09VcEZCRERjRGVfckp4cHU1Sks3MDJvIn0.eyJqdGkiOiIzOWQxMmU1NC00MjliLTRkZjUtOTM2OS01YWVlOTFkNzAwZjgiLCJleHAiOjE0ODg5MDk1NzMsIm5iZiI6MCwiaWF0IjoxNDg4OTA5MjczLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgxODAvYXV0aC9yZWFsbXMvRGVtbyIsImF1ZCI6ImJvb3QtYXBwIiwic3ViIjoiNGM5NjE5NDQtN2VkZC00ZDZiLTg2MGUtYmJiZGNhODk0MDU4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYm9vdC1hcHAiLCJhdXRoX3RpbWUiOjE0ODg5MDkyNzMsInNlc3Npb25fc3RhdGUiOiJiMjdjMDZlNi02ODgwLTQxZTEtOTM2MS1jZmEzYzY2ZjYyNjAiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIyYjA5NTFiOC1iMjdkLTRlYWMtYjUxOC1kZTQ5OTA5OTY2ZDgiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYm9vdC1hcGkiOnsicm9sZXMiOlsiYm9vdC1hcGktcm9sZSJdfSwiYm9vdC1hcHAiOnsicm9sZXMiOlsiYm9vdC1yb2xlIl19fSwibmFtZSI6IkFsaWNlICIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiIiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUubmV0In0.NfF5rPMabu8gaigUHZnX3gIzNGAxKpmPP206U5keNtexNqsmQEFO4KT2i1JYLwvNVFnRWCa8FmYokAtzeHgLvHk2B8CZXqL6GSMGQ26wPS5RIFTak9HjfHMhodqSIdy4wZTKmEcum_uYTaCdrVRSfWU8l94xAY6OzwElZX5ulkucvgWQnpFs0HB7X54kB07OqpN8L3i1jeQoEV0iJchtxZiEOSipqMNO7cujMqB_6lf9i78URPuyExfeLzAWyDbMWSJBp3zUoS7HakwE_4oC3eVEYTxDtMRL2yl2_8R0C0g2Dc0Qb9aezFxo3-SDNuy9aicDmibEEOpIoetlrIYbNA";

		OAuth2AccessToken accessToken = jwkTokenStore.readAccessToken(jwt);
		assertEquals(issuer, accessToken.getAdditionalInformation().get("iss"));
	}

	private void setUpResponses(String issuer) {
		String jwkSetUri = this.server.url("").toString();

		this.server.enqueue(new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(
				"	{\n" +
				"   	\"issuer\": \"" + issuer + "\",\n" +
				"   	\"authorization_endpoint\": \"http://localhost:8180/oauth/authorize\",\n" +
				"   	\"token_endpoint\": \"http://localhost:8180/oauth/token\",\n" +
				"   	\"userinfo_endpoint\": \"http://localhost:8180/userinfo\",\n" +
				"   	\"jwks_uri\": \"" + jwkSetUri + "\"\n" +
				"	}\n"));

		this.server.enqueue(new MockResponse().setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).setBody("{\n" +
				"    \"keys\": [\n" +
				"        {\n" +
				"            \"kid\": \"_Ci3-VfV_N0YAG22NQOgOUpFBDDcDe_rJxpu5JK702o\",\n" +
				"            \"kty\": \"RSA\",\n" +
				"            \"alg\": \"RS256\",\n" +
				"            \"use\": \"sig\",\n" +
				"            \"n\": \"rne3dowbQHcFCzg2ejWb6az5QNxWFiv6kRpd34VDzYNMhWeewfeEL5Pf5clE8Xh1KlllrDYSxtnzUQm-t9p92yEBASfV96ydTYG-ITfxfJzKtJUN-iIS5K9WGYXnDNS4eYZ_ygW-zBU_9NwFMXdwSTzRqHeJmLJrfbmmjoIuuWyfh2Ko52KzyidceR5SJxGeW0ckeyWka1lDf4cr7fv-s093Y_sd2wrNvg0-9IAkXotbxWWXcfMgXFyw0qHFT_5LrKmiwkY3HCaiV5NgEFJmC6fBIG2EOZG4rqjBoYV6LZwrfTMHknaeel9MOZesW6SR2bswtuuWN3DGq2zg0KamLw\",\n" +
				"            \"e\": \"AQAB\"\n" +
				"        }\n" +
				"    ]\n" +
				"}\n"));
	}
}