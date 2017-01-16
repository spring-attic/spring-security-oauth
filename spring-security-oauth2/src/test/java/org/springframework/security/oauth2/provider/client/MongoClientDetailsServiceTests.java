package org.springframework.security.oauth2.provider.client;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.mongo.MongoClientDetails;
import org.springframework.security.oauth2.provider.client.mongo.MongoClientDetailsService;
import org.springframework.util.StringUtils;

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
public class MongoClientDetailsServiceTests {

	private static final String DATABASE = "test";
	private static final String HOST = "localhost";
	private static final int PORT = 12345;

	private MongodStarter starter = MongodStarter.getDefaultInstance();
	private MongodExecutable mongodExecutable = null;
	private MongoClientDetailsService clientDetailsService;

	public MongoClientDetailsService clientDetailsService() {
		return this.clientDetailsService;
	}

	@Before
	public void setUp() throws Exception {
		IMongodConfig mongodConfig = new MongodConfigBuilder()
				.version(Version.Main.PRODUCTION)
				.net(new Net(PORT, Network.localhostIsIPv6())).build();
		mongodExecutable = starter.prepare(mongodConfig);
		mongodExecutable.start();
		clientDetailsService = new MongoClientDetailsService(
				new MongoTemplate(new MongoClient(HOST, PORT), DATABASE));
	}

	@After
	public void destroy() throws Exception {
		if (mongodExecutable != null)
			mongodExecutable.stop();
	}

	@Test(expected = NoSuchClientException.class)
	public void testLoadingClientForNonExistingClientId() {
		clientDetailsService().loadClientByClientId("nonExistingClientId");
	}

	@Test
	public void testLoadingClientIdWithNoDetails() {
		String clientId = "clientIdWithNoDetails";
		this.clientDetailsService().addClientDetails(new MongoClientDetails(clientId,
				null, null, null, null, null, null, null, null, null, null));

		ClientDetails clientDetails = clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, clientDetails.getClientId());
		assertFalse(clientDetails.isSecretRequired());
		assertNull(clientDetails.getClientSecret());
		assertFalse(clientDetails.isScoped());
		assertEquals(0, clientDetails.getScope().size());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		assertNull(clientDetails.getRegisteredRedirectUri());
		assertEquals(0, clientDetails.getAuthorities().size());
		assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
		assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithAdditionalInformation() {
		String clientId = "clientIdWithAddInfo";
		Map<String, Object> additionalInformation = new HashMap<String, Object>();
		additionalInformation.put("foo", "bar");

		this.clientDetailsService()
				.addClientDetails(new MongoClientDetails(clientId, null, null, null, null,
						null, null, null, null, null, additionalInformation));

		ClientDetails clientDetails = clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, clientDetails.getClientId());
		assertEquals(Collections.singletonMap("foo", "bar"),
				clientDetails.getAdditionalInformation());
	}

	@Test
	public void testLoadingClientIdWithSingleDetails() {
		String clientId = "clientIdWithSingleDetails";
		String clientSecret = "mySecret";
		Set<String> scope = StringUtils.commaDelimitedListToSet("myScope");
		Set<String> resourceIds = StringUtils.commaDelimitedListToSet("myResource");
		Set<String> redirectUri = StringUtils.commaDelimitedListToSet("myRedirectUri");
		Set<String> grantType = StringUtils
				.commaDelimitedListToSet("myAuthorizedGrantType");
		Set<String> authority = StringUtils.commaDelimitedListToSet("myAuthority");
		int accessTokenValidity = 100;
		int refreshTokenValidity = 200;
		String autoApprove = "true";

		MongoClientDetails mongoClientDetails = new MongoClientDetails(clientId,
				clientSecret, scope, resourceIds, grantType, redirectUri, null, authority,
				accessTokenValidity, refreshTokenValidity, null);
		mongoClientDetails.isAutoApprove(autoApprove);

		this.clientDetailsService().addClientDetails(mongoClientDetails);

		ClientDetails clientDetails = clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals(clientSecret, clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals(scope, clientDetails.getScope());
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals(resourceIds, clientDetails.getResourceIds());
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals(grantType, clientDetails.getAuthorizedGrantTypes());
		assertEquals(redirectUri, clientDetails.getRegisteredRedirectUri());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals(Integer.valueOf(accessTokenValidity),
				clientDetails.getAccessTokenValiditySeconds());
		assertEquals(Integer.valueOf(refreshTokenValidity),
				clientDetails.getRefreshTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithMultipleDetails() {
		String clientId = "clientIdWithMultipleDetails";
		String clientSecret = "mySecret";
		Set<String> resources = StringUtils
				.commaDelimitedListToSet("myResource1,myResource2");
		Set<String> scopes = StringUtils.commaDelimitedListToSet("myScope1,myScope2");
		Set<String> grantType = StringUtils
				.commaDelimitedListToSet("myAuthorizedGrantType1,myAuthorizedGrantType2");
		Set<String> redirectUri = StringUtils
				.commaDelimitedListToSet("myRedirectUri1,myRedirectUri2");
		Set<String> authority = StringUtils
				.commaDelimitedListToSet("myAuthority1,myAuthority2");
		Integer accessTokenValidity = 100;
		Integer refreshTokenValidity = 200;
		Set<String> autoapprove = StringUtils.commaDelimitedListToSet("read,write");

		MongoClientDetails clientDetails = new MongoClientDetails(clientId, clientSecret,
				scopes, resources, grantType, redirectUri, autoapprove, authority,
				accessTokenValidity, refreshTokenValidity, null);

		this.clientDetailsService().addClientDetails(clientDetails);

		ClientDetails loadedDetails = this.clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, loadedDetails.getClientId());
		assertTrue(loadedDetails.isSecretRequired());
		assertEquals("mySecret", loadedDetails.getClientSecret());
		assertTrue(loadedDetails.isScoped());
		assertEquals(2, loadedDetails.getResourceIds().size());
		Iterator<String> resourceIds = loadedDetails.getResourceIds().iterator();
		assertEquals("myResource1", resourceIds.next());
		assertEquals("myResource2", resourceIds.next());
		assertEquals(2, loadedDetails.getScope().size());
		Iterator<String> scope = loadedDetails.getScope().iterator();
		assertEquals("myScope1", scope.next());
		assertEquals("myScope2", scope.next());
		assertEquals(2, loadedDetails.getAuthorizedGrantTypes().size());
		Iterator<String> grantTypes = loadedDetails.getAuthorizedGrantTypes().iterator();
		assertEquals("myAuthorizedGrantType1", grantTypes.next());
		assertEquals("myAuthorizedGrantType2", grantTypes.next());
		assertEquals(2, loadedDetails.getRegisteredRedirectUri().size());
		Iterator<String> redirectUris = loadedDetails.getRegisteredRedirectUri()
				.iterator();
		assertEquals("myRedirectUri1", redirectUris.next());
		assertEquals("myRedirectUri2", redirectUris.next());
		assertEquals(2, loadedDetails.getAuthorities().size());
		Iterator<GrantedAuthority> authorities = loadedDetails.getAuthorities()
				.iterator();
		assertEquals("myAuthority1", authorities.next().getAuthority());
		assertEquals("myAuthority2", authorities.next().getAuthority());
		assertEquals(new Integer(100), loadedDetails.getAccessTokenValiditySeconds());
		assertEquals(new Integer(200), loadedDetails.getRefreshTokenValiditySeconds());
		assertTrue(loadedDetails.isAutoApprove("read"));
	}

	@Test
	public void testAddClientWithNoDetails() {
		String clientId = "addedClientIdWithNoDetails";

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId(clientId);

		clientDetailsService().addClientDetails(clientDetails);
		ClientDetails details = this.clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, details.getClientId());
		assertEquals(null, details.getClientSecret());
	}

	@Test(expected = ClientAlreadyExistsException.class)
	public void testInsertDuplicateClient() {

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId("duplicateClientIdWithNoDetails");

		clientDetailsService().addClientDetails(clientDetails);
		clientDetailsService().addClientDetails(clientDetails);
	}

	@Test
	public void testUpdateClientSecret() {
		String clientId = "newClientIdWithNoDetails";

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId(clientId);

		clientDetailsService().setPasswordEncoder(new PasswordEncoder() {

			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return true;
			}

			public String encode(CharSequence rawPassword) {
				return "BAR";
			}
		});
		clientDetailsService().addClientDetails(clientDetails);
		clientDetailsService().updateClientSecret(clientDetails.getClientId(), "foo");

		ClientDetails details = this.clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, details.getClientId());
		assertTrue(!details.getClientSecret().isEmpty());
		assertEquals("BAR", details.getClientSecret());
	}

	@Test
	public void testUpdateClientRedirectURI() {

		String clientId = "newClientIdWithNoDetails";

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId(clientId);

		clientDetailsService().addClientDetails(clientDetails);

		String[] redirectURI = { "http://localhost:8080", "http://localhost:9090" };
		clientDetails.setRegisteredRedirectUri(
				new HashSet<String>(Arrays.asList(redirectURI)));

		clientDetailsService().updateClientDetails(clientDetails);

		ClientDetails clientDetailsFound = this.clientDetailsService()
				.loadClientByClientId(clientId);

		assertEquals(clientId, clientDetailsFound.getClientId());
		assertTrue(!clientDetailsFound.getRegisteredRedirectUri().isEmpty());
		assertEquals(2, clientDetailsFound.getRegisteredRedirectUri().size());
	}

	@Test(expected = NoSuchClientException.class)
	public void testUpdateNonExistentClient() {

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId("nosuchClientIdWithNoDetails");

		clientDetailsService().updateClientDetails(clientDetails);
	}

	@Test(expected = NoSuchClientException.class)
	public void testRemoveClient() {
		String clientId = "deletedClientIdWithNoDetails";

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId(clientId);

		clientDetailsService().addClientDetails(clientDetails);
		clientDetailsService().removeClientDetails(clientDetails.getClientId());

		clientDetailsService().loadClientByClientId(clientId);
	}

	@Test(expected = NoSuchClientException.class)
	public void testRemoveNonExistentClient() {

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId("nosuchClientIdWithNoDetails");

		clientDetailsService().removeClientDetails(clientDetails.getClientId());
	}

	@Test
	public void testFindClients() {

		MongoClientDetails clientDetails = new MongoClientDetails();
		clientDetails.setClientId("aclient");

		clientDetailsService().addClientDetails(clientDetails);
		int count = clientDetailsService().listClientDetails().size();

		assertEquals(1, count);
	}

}
