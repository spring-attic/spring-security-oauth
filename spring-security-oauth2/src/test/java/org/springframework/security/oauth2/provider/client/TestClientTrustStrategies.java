package org.springframework.security.oauth2.provider.client;

import java.util.HashMap;

import org.junit.Test;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import static org.junit.Assert.assertEquals;


public class TestClientTrustStrategies {
	
	private ClientTrustStrategy implicitStrategy = new ImplicitClientTrustStrategy();
	
	private ClientTrustStrategy notTrustedStrategy = new NotTrustedClientTrustStrategy();
	
	private AuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state, String scope, String responseType) {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("redirect_uri", redirectUri);
		parameters.put("state", state);
		parameters.put("scope", scope);
		parameters.put("response_type", responseType);
		return new AuthorizationRequest(parameters);
	}
	
	private AuthorizationRequest getTokenRequest() {
		return getAuthorizationRequest("foo", "http://anywhere.com", "bar", "baz", "token");
	}
	
	private AuthorizationRequest getAutorizationCodeRequest() {
		return getAuthorizationRequest("foo", "http://anywhere.com", "bar", "baz", "code");
	}
	
	@Test
	public void testImplicitAuthorizationRequest() {
		AuthorizationRequest request = getTokenRequest();
		
		boolean result = implicitStrategy.canSkipApproval(new AuthorizationRequestHolder(request, null));
		
		assertEquals(result, true);
	}
	
	@Test
	public void testAuthorizationCodeAuthorizationRequest() {
		AuthorizationRequest request = getAutorizationCodeRequest();
		
		boolean result = implicitStrategy.canSkipApproval(new AuthorizationRequestHolder(request, null));
		
		assertEquals(result, false);
	}
	
	@Test
	public void testImplicitAuthorizationRequestNotTrusted() {
		AuthorizationRequest request = getTokenRequest();
		
		boolean result = notTrustedStrategy.canSkipApproval(new AuthorizationRequestHolder(request, null));
		
		assertEquals(result, false);
	}
	
	@Test
	public void testAuthorizationCodeAuthorizationRequestNotTrusted() {
		AuthorizationRequest request = getAutorizationCodeRequest();
		
		boolean result = notTrustedStrategy.canSkipApproval(new AuthorizationRequestHolder(request, null));
		
		assertEquals(result, false);
	}

}
