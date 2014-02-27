package org.springframework.security.oauth.consumer;

import java.util.HashMap;

import org.junit.Test;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.consumer.client.CoreOAuthConsumerSupport;
import org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory;

/**
 * @author Ryan Heaton
 */
public class GoogleOAuthTests {

	/**
	 * tests getting a request token.
	 */
	@Test
	public void testGetRequestToken() throws Exception {
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport();
		support.setStreamHandlerFactory(new DefaultOAuthURLStreamHandlerFactory());
		InMemoryProtectedResourceDetailsService service = new InMemoryProtectedResourceDetailsService();
		HashMap<String, ProtectedResourceDetails> detailsStore = new HashMap<String, ProtectedResourceDetails>();
		BaseProtectedResourceDetails googleDetails = new BaseProtectedResourceDetails();
		googleDetails.setRequestTokenURL("https://www.google.com/accounts/OAuthGetRequestToken");
		googleDetails.setAccessTokenURL("https://www.google.com/accounts/OAuthAuthorizeToken");
		googleDetails.setConsumerKey("anonymous");
		googleDetails.setSharedSecret(new SharedConsumerSecretImpl("anonymous"));
		googleDetails.setId("google");
		googleDetails.setUse10a(true);
		googleDetails.setSignatureMethod(HMAC_SHA1SignatureMethod.SIGNATURE_NAME);
		googleDetails.setRequestTokenHttpMethod("GET");
		HashMap<String, String> additional = new HashMap<String, String>();
		additional.put("scope", "http://picasaweb.google.com/data");
		googleDetails.setAdditionalParameters(additional);
		detailsStore.put(googleDetails.getId(), googleDetails);
		service.setResourceDetailsStore(detailsStore);
		support.setProtectedResourceDetailsService(service);
		// uncomment to see a request to google.
		// see http://code.google.com/apis/accounts/docs/OAuth_ref.html
		// and http://jira.codehaus.org/browse/OAUTHSS-37
		// OAuthConsumerToken token = support.getUnauthorizedRequestToken("google", "urn:mycallback");
		// System.out.println(token.getValue());
		// System.out.println(token.getSecret());
	}
}
