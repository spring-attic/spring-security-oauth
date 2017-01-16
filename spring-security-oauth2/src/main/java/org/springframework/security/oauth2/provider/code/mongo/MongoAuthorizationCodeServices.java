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

package org.springframework.security.oauth2.provider.code.mongo;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.util.Assert;

/**
 * Default MongoDB implementation of AuthorizationCodeServices.
 * 
 * @author Marcos Barbero
 */
public class MongoAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	private static final String CODE = "code";

	private final MongoTemplate mongoTemplate;

	public MongoAuthorizationCodeServices(MongoTemplate mongoTemplate) {
		Assert.notNull(mongoTemplate, "The mongoTemplate cannot be null.");
		this.mongoTemplate = mongoTemplate;
	}

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		this.mongoTemplate.insert(new MongoAuthCode(null, code,
				SerializationUtils.serialize(authentication)));
	}

	@Override
	protected OAuth2Authentication remove(String code) {
		OAuth2Authentication authentication = null;
		MongoAuthCode authCode = this.mongoTemplate.findOne(findByCode(code),
				MongoAuthCode.class);

		if (authCode != null) {
			authentication = SerializationUtils.deserialize(authCode.getAuthentication());
			this.mongoTemplate.remove(authCode);
		}
		return authentication;
	}

	/**
	 * Create a Query to find by code.
	 * 
	 * @param code The code
	 * @return Query
	 */
	private Query findByCode(final String code) {
		return new Query(Criteria.where(CODE).is(code));
	}
}
