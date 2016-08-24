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

package org.springframework.security.oauth2.provider.client.mongo;

import java.util.ArrayList;
import java.util.List;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.*;
import org.springframework.util.Assert;

import com.mongodb.WriteResult;

/**
 * Basic, MongoDB implementation of the client details service.
 *
 * @author Marcos Barbero
 */
public class MongoClientDetailsService
		implements ClientDetailsService, ClientRegistrationService {

	private static final String CLIENT_ID = "clientId";

	private static final String CLIENT_SECRET = "clientSecret";

	private static final String SCOPE = "scope";

	private static final String RESOURCE_IDS = "resourceIds";

	private static final String AUTHORIZED_GRANT_TYPES = "authorizedGrantTypes";

	private static final String REGISTERED_REDIRECT_URI = "registeredRedirectUris";

	private static final String AUTO_APPROVE = "autoApproveScopes";

	private static final String AUTHORITIES = "authorities";

	private static final String ACCESS_TOKEN_VALIDITY = "accessTokenValiditySeconds";

	private static final String REFRESH_TOKEN_VALIDITY = "refreshTokenValiditySeconds";

	private static final String ADDITIONAL_INFORMATION = "additionalInformation";

	private final MongoTemplate mongoTemplate;

	private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

	public MongoClientDetailsService(MongoTemplate mongoTemplate) {
		Assert.notNull(mongoTemplate, "MongoTemplate required.");
		this.mongoTemplate = mongoTemplate;
	}

	public MongoClientDetailsService(MongoTemplate mongoTemplate,
			PasswordEncoder passwordEncoder) {
		Assert.notNull(mongoTemplate, "MongoTemplate required.");
		Assert.notNull(passwordEncoder, "PasswordEncoder required.");
		this.mongoTemplate = mongoTemplate;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * @param passwordEncoder the password encoder to set
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public ClientDetails loadClientByClientId(String clientId)
			throws ClientRegistrationException {
		ClientDetails clientDetails = this.mongoTemplate.findOne(findByClientId(clientId),
				MongoClientDetails.class);
		if (clientDetails == null) {
			throw new NoSuchClientException("No client with requested id: " + clientId);
		}
		return clientDetails;
	}

	@Override
	public void addClientDetails(ClientDetails clientDetails)
			throws ClientAlreadyExistsException {
		try {
			MongoClientDetails mongoClientDetails = (MongoClientDetails) clientDetails;
			if (mongoClientDetails.getClientSecret() != null) {
				mongoClientDetails.setClientSecret(this.passwordEncoder
						.encode(mongoClientDetails.getClientSecret()));
			}
			this.mongoTemplate.insert(clientDetails);
		}
		catch (DuplicateKeyException e) {
			throw new ClientAlreadyExistsException(
					"Client already exists: " + clientDetails.getClientId(), e);
		}
	}

	@Override
	public void updateClientDetails(ClientDetails clientDetails)
			throws NoSuchClientException {
		WriteResult result = this.mongoTemplate.updateFirst(
				findByClientId(clientDetails.getClientId()),
				getUpdateFields((MongoClientDetails) clientDetails),
				MongoClientDetails.class);
		if (result.getN() != 1) {
			throw new NoSuchClientException(
					"No client found with id: " + clientDetails.getClientId());
		}
	}

	@Override
	public void updateClientSecret(String clientId, String secret)
			throws NoSuchClientException {
		WriteResult result = this.mongoTemplate.updateFirst(findByClientId(clientId),
				getUpdateSecret(secret), MongoClientDetails.class);
		if (result == null) {
			throw new NoSuchClientException("No client found with id: " + clientId);
		}
	}

	@Override
	public void removeClientDetails(String clientId) throws NoSuchClientException {
		WriteResult result = this.mongoTemplate.remove(findByClientId(clientId),
				MongoClientDetails.class);
		if (result.getN() != 1) {
			throw new NoSuchClientException("No client found with id: " + clientId);
		}
	}

	@Override
	public List<ClientDetails> listClientDetails() {
		return new ArrayList<ClientDetails>(
				this.mongoTemplate.findAll(MongoClientDetails.class));
	}

	/**
	 * Creates a ${@link Query} to find by clientId.
	 *
	 * @param clientId The clientId to look for
	 * @return A ${@link Query}
	 */
	private Query findByClientId(final String clientId) {
		return new Query(Criteria.where(CLIENT_ID).is(clientId));
	}

	/**
	 * Create the ${@link Update} object with proper fields to be updated.
	 *
	 * @param clientDetails The ${@link MongoClientDetails} to be updated
	 * @return The ${@link Update} object
	 */
	private Update getUpdateFields(final MongoClientDetails clientDetails) {
		Update update = new Update();
		update.set(ACCESS_TOKEN_VALIDITY, clientDetails.getAccessTokenValiditySeconds());
		update.set(ADDITIONAL_INFORMATION, clientDetails.getAdditionalInformation());
		update.set(AUTHORITIES, clientDetails.getAuthorities());
		update.set(AUTHORIZED_GRANT_TYPES, clientDetails.getAuthorizedGrantTypes());
		update.set(AUTO_APPROVE, clientDetails.getAutoApproveScopes());
		String clientSecret = clientDetails.getClientSecret() != null
				? passwordEncoder.encode(clientDetails.getClientSecret()) : null;
		update.set(CLIENT_SECRET, clientSecret);
		update.set(REFRESH_TOKEN_VALIDITY,
				clientDetails.getRefreshTokenValiditySeconds());
		update.set(REGISTERED_REDIRECT_URI, clientDetails.getRegisteredRedirectUri());
		update.set(RESOURCE_IDS, clientDetails.getResourceIds());
		update.set(SCOPE, clientDetails.getScope());
		return update;
	}

	/**
	 * Create an ${@link Update} object with client_secret key/value to be updated.
	 *
	 * @param clientSecret The new clientSecret
	 * @return The ${@link Update} object
	 */
	private Update getUpdateSecret(final String clientSecret) {
		return Update.update(CLIENT_SECRET, passwordEncoder.encode(clientSecret));
	}

}
