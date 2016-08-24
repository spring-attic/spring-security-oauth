package org.springframework.security.oauth2.client.token;

import org.junit.After;
import org.junit.Before;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.oauth2.client.token.mongo.MongoClientTokenServices;

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
public class MongoClientTokenServicesTests extends ClientTokenServicesBaseTests {

	private static final String DATABASE = "test";
	private static final String HOST = "localhost";
	private static final int PORT = 12345;

	private MongodStarter starter = MongodStarter.getDefaultInstance();
	private MongoClientTokenServices tokenServices;
	private MongodExecutable mongodExecutable = null;

	@Override
	public MongoClientTokenServices getTokenServices() {
		return tokenServices;
	}

	@Before
	public void setUp() throws Exception {
		IMongodConfig mongodConfig = new MongodConfigBuilder()
				.version(Version.Main.PRODUCTION)
				.net(new Net(PORT, Network.localhostIsIPv6())).build();
		mongodExecutable = starter.prepare(mongodConfig);
		mongodExecutable.start();
		this.tokenServices = new MongoClientTokenServices(
				new MongoTemplate(new MongoClient(HOST, PORT), DATABASE));
	}

	@After
	public void destroy() throws Exception {
		if (mongodExecutable != null)
			mongodExecutable.stop();
	}

}
