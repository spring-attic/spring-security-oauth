package org.springframework.security.oauth2.client.token.mongo;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientKeyGenerator;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.client.token.DefaultClientKeyGenerator;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.util.Assert;

/**
 * Default MongoDB implementation of ClientTokenServices.
 * 
 * @author Marcos Barbero
 */
public class MongoClientTokenServices implements ClientTokenServices {

	private static final String AUTHENTICATION_ID = "authenticationId";

	private final MongoTemplate mongoTemplate;

	private ClientKeyGenerator clientKeyGenerator = new DefaultClientKeyGenerator();

	public MongoClientTokenServices(MongoTemplate mongoTemplate) {
		Assert.notNull(mongoTemplate, "The mongoTemplate cannot be null");
		this.mongoTemplate = mongoTemplate;
	}

	public MongoClientTokenServices(MongoTemplate mongoTemplate,
			ClientKeyGenerator clientKeyGenerator) {
		Assert.notNull(mongoTemplate, "The mongoTemplate cannot be null");
		Assert.notNull(clientKeyGenerator, "The clientKeyGenerator cannot be null");
		this.mongoTemplate = mongoTemplate;
		this.clientKeyGenerator = clientKeyGenerator;
	}

	public void setClientKeyGenerator(ClientKeyGenerator clientKeyGenerator) {
		this.clientKeyGenerator = clientKeyGenerator;
	}

	@Override
	public OAuth2AccessToken getAccessToken(final OAuth2ProtectedResourceDetails resource,
			final Authentication authentication) {
		OAuth2AccessToken accessToken = null;
		final String authenticationId = this.clientKeyGenerator.extractKey(resource,
				authentication);
		final MongoOAuthClientToken clientToken = this.mongoTemplate.findOne(
				findByAuthenticationId(authenticationId), MongoOAuthClientToken.class);
		if (clientToken != null) {
			accessToken = SerializationUtils.deserialize(clientToken.getToken());
		}
		return accessToken;
	}

	@Override
	public void saveAccessToken(final OAuth2ProtectedResourceDetails resource,
			final Authentication authentication, final OAuth2AccessToken accessToken) {
		removeAccessToken(resource, authentication);
		String name = authentication == null ? null : authentication.getName();
		final MongoOAuthClientToken clientToken = new MongoOAuthClientToken(null,
				accessToken.getValue(), SerializationUtils.serialize(accessToken),
				this.clientKeyGenerator.extractKey(resource, authentication), name,
				resource.getClientId());
		this.mongoTemplate.insert(clientToken);
	}

	@Override
	public void removeAccessToken(final OAuth2ProtectedResourceDetails resource,
			final Authentication authentication) {
		final String authenticationId = this.clientKeyGenerator.extractKey(resource,
				authentication);
		this.mongoTemplate.remove(findByAuthenticationId(authenticationId),
				MongoOAuthClientToken.class);
	}

	/**
	 * Create a Query to filter by authenticationId.
	 * 
	 * @param authenticationId The authenticationId
	 * @return A Query
	 */
	private Query findByAuthenticationId(final String authenticationId) {
		return Query.query(Criteria.where(AUTHENTICATION_ID).is(authenticationId));
	}
}
