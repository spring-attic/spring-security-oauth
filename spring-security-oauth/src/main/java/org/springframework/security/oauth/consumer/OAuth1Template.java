package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.web.util.UriTemplate;

public class OAuth1Template {
	private final String consumerKey;

	private final String consumerSecret;

	private final String requestTokenUrl;

	private final UriTemplate authorizeUrlTemplate;

	private final String accessTokenUrl;

	private OAuthConsumerSupport consumerSupport;

	public OAuth1Template(String consumerKey, String consumerSecret, String requestTokenUrl, String authorizeUrl,
			String accessTokenUrl) {
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
		this.requestTokenUrl = requestTokenUrl;
		this.authorizeUrlTemplate = new UriTemplate(authorizeUrl);
		this.accessTokenUrl = accessTokenUrl;

		consumerSupport = new CoreOAuthConsumerSupport();
	}

	public OAuthToken fetchNewRequestToken(String callbackUrl) {
		BaseProtectedResourceDetails details = new BaseProtectedResourceDetails();
		details.setConsumerKey(consumerKey);
		details.setSharedSecret(new SharedConsumerSecret(consumerSecret));
		details.setRequestTokenURL(requestTokenUrl);
		OAuthConsumerToken requestToken = consumerSupport.getUnauthorizedRequestToken(details, callbackUrl);
		return new OAuthToken(requestToken.getValue(), requestToken.getSecret());
	}

	public String buildAuthorizeUrl(String requestToken) {
		return authorizeUrlTemplate.expand(requestToken).toString();
	}
}
