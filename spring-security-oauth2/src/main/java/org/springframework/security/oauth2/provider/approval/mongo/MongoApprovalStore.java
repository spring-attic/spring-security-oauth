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

package org.springframework.security.oauth2.provider.approval.mongo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.springframework.beans.BeanUtils;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.util.Assert;

import com.mongodb.WriteResult;

/**
 * Default MongoDB implementation of ApprovalStore.
 * 
 * @author Marcos Barbero
 */
public class MongoApprovalStore implements ApprovalStore {

	private static final String CLIENT_ID = "clientId";
	private static final String USER_ID = "userId";
	private static final String SCOPE = "scope";
	private static final String LAST_UPDATED_AT = "lastUpdatedAt";
	private static final String EXPIRES_AT = "expiresAt";
	private static final String STATUS = "status";
	private final MongoTemplate mongoTemplate;
	private boolean handleRevocationsAsExpiry = false;

	public MongoApprovalStore(MongoTemplate mongoTemplate) {
		Assert.notNull(mongoTemplate, "The mongoTemplate cannot be null.");
		this.mongoTemplate = mongoTemplate;
	}

	@Override
	public boolean addApprovals(final Collection<Approval> approvals) {
		boolean success = true;
		final Collection<MongoApproval> mongoApprovals = mongoApprovals(approvals);
		for (MongoApproval mongoApproval : mongoApprovals) {
			if (!upsert(mongoApproval)) {
				success = false;
			}
		}
		return success;
	}

	@Override
	public boolean revokeApprovals(final Collection<Approval> approvals) {
		boolean success = true;
		final Collection<MongoApproval> mongoApprovals = mongoApprovals(approvals);
		for (final MongoApproval mongoApproval : mongoApprovals) {
			if (this.handleRevocationsAsExpiry) {
				WriteResult result = this.mongoTemplate.updateFirst(
						findByUserIdAndClientIdAndScope(mongoApproval),
						updateExpiresAt(mongoApproval.getExpiresAt()),
						MongoApproval.class);

				if (result.getN() != 1) {
					success = false;
				}
			}
			else {
				WriteResult result = this.mongoTemplate.remove(
						findByUserIdAndClientIdAndScope(mongoApproval),
						MongoApproval.class);
				if (result.getN() != 1) {
					success = false;
				}
			}
		}
		return success;
	}

	@Override
	public Collection<Approval> getApprovals(final String userId, final String clientId) {
		final List<MongoApproval> mongoApprovals = this.mongoTemplate
				.find(findByUserIdAndClientId(userId, clientId), MongoApproval.class);
		return approvals(mongoApprovals);
	}

	public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
		this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
	}

	/**
	 * Execute MongoDB upsert operation.
	 *
	 * @param mongoApproval The MongoApproval
	 * @return Flag indicating success or not
	 */
	private boolean upsert(final MongoApproval mongoApproval) {
		WriteResult result = this.mongoTemplate.upsert(
				findByUserIdAndClientIdAndScope(mongoApproval),
				updateFields(mongoApproval), MongoApproval.class);
		return result.getN() == 1;
	}

	/**
	 * Create a Query to find by userId and clientId.
	 * 
	 * @param userId The userId
	 * @param clientId The clientId
	 * @return A Query
	 */
	private Query findByUserIdAndClientId(final String userId, final String clientId) {
		return Query.query(Criteria.where(USER_ID).is(userId)
				.andOperator(Criteria.where(CLIENT_ID).is(clientId)));
	}

	/**
	 * Create a Query to filter by userId, clientId and scope.
	 * 
	 * @param mongoApproval MongoApproval
	 * @return Query
	 */
	private Query findByUserIdAndClientIdAndScope(final MongoApproval mongoApproval) {
		return Query.query(Criteria.where(USER_ID).is(mongoApproval.getUserId())
				.andOperator(Criteria.where(CLIENT_ID).is(mongoApproval.getClientId())
						.andOperator(
								Criteria.where(SCOPE).is(mongoApproval.getScope()))));
	}

	/**
	 * Create an Update object from MongoApproval
	 * 
	 * @param mongoApproval The MongoApproval
	 * @return Update
	 */
	private Update updateFields(final MongoApproval mongoApproval) {
		return Update.update(EXPIRES_AT, mongoApproval.getExpiresAt())
				.set(STATUS, mongoApproval.getStatus())
				.set(LAST_UPDATED_AT, mongoApproval.getLastUpdatedAt());
	}

	/**
	 * Create an Update object to update expiresAt.
	 * 
	 * @param expiresAt The expiresAt
	 * @return Updated
	 */
	private Update updateExpiresAt(final Date expiresAt) {
		return Update.update(EXPIRES_AT, expiresAt);
	}

	/**
	 * Convert a collection of Approval to a collection of MongoApproval.
	 *
	 * @param approvals A collection of approval
	 * @return A collection of MongoApproval
	 */
	private Collection<MongoApproval> mongoApprovals(
			final Collection<Approval> approvals) {
		Collection<MongoApproval> mongoApprovals = new ArrayList<MongoApproval>();
		for (Approval approval : approvals) {
			mongoApprovals.add(toMongoApproval(approval));
		}
		return mongoApprovals;
	}

	/**
	 * Convert a collection of MongoApproval to a collection of Approval.
	 *
	 * @param mongoApprovals A collection of approval
	 * @return A collection of Approval
	 */
	private Collection<Approval> approvals(
			final Collection<MongoApproval> mongoApprovals) {
		Collection<Approval> approvals = new ArrayList<Approval>();
		for (MongoApproval mongoApproval : mongoApprovals) {
			approvals.add(toApproval(mongoApproval));
		}
		return approvals;
	}

	/**
	 * Copy properties from Approval to MongoApproval.
	 *
	 * @param approval The Approval
	 * @return MongoApproval
	 */
	private MongoApproval toMongoApproval(final Approval approval) {
		MongoApproval mongoApproval = new MongoApproval();
		BeanUtils.copyProperties(approval, mongoApproval);
		if (mongoApproval.getStatus() == null) {
			mongoApproval.setStatus(ApprovalStatus.APPROVED);
		}
		return mongoApproval;
	}

	/**
	 * Copy properties from MongoApproval to Approval.
	 * 
	 * @param mongoApproval The MongoApproval
	 * @return Approval
	 */
	private Approval toApproval(final MongoApproval mongoApproval) {
		return new Approval(mongoApproval.getUserId(), mongoApproval.getClientId(),
				mongoApproval.getScope(), mongoApproval.getExpiresAt(),
				mongoApproval.getStatus(), mongoApproval.getLastUpdatedAt());
	}

}
