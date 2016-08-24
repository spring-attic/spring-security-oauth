package org.springframework.security.oauth2.provider.approval.mongo;

import org.junit.After;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.oauth2.provider.approval.AbstractTestApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;

import com.mongodb.MongoClient;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;

/**
 * @author Marcos Barbero
 */
public class MongoApprovalStoreTests extends AbstractTestApprovalStore {

	private static final String DATABASE = "test";
	private static final String HOST = "localhost";
	private static final int PORT = 12345;

	private MongodStarter starter = MongodStarter.getDefaultInstance();
	private MongoApprovalStore mongoApprovalStore;
	private MongodExecutable mongodExecutable = null;

	@Override
	protected ApprovalStore getApprovalStore() {
		this.setUp();
		return mongoApprovalStore;
	}

	@After
	public void destroy() throws Exception {
		if (mongodExecutable != null)
			mongodExecutable.stop();
	}

	private void setUp() {
		try {
			IMongodConfig mongodConfig = new MongodConfigBuilder()
					.version(Version.Main.PRODUCTION)
					.net(new Net(PORT, Network.localhostIsIPv6())).build();
			mongodExecutable = starter.prepare(mongodConfig);
			mongodExecutable.start();
			this.mongoApprovalStore = new MongoApprovalStore(
					new MongoTemplate(new MongoClient(HOST, PORT), DATABASE));
		}
		catch (Exception ex) {
			throw new RuntimeException();
		}
	}
}
