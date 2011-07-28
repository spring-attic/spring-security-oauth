package org.springframework.security.oauth2.provider;

import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;

/**
 * <p> A rule that prevents integration tests from failing if the server application is not running or not accessible.
 * If the server is not running in the background all the tests here will simply be skipped because of a violated
 * assumption (showing as successful). Usage: </p>
 * 
 * <pre> &#064;Rule public static BrokerRunning brokerIsRunning = BrokerRunning.isRunning();
 * 
 * &#064;Test public void testSendAndReceive() throws Exception { // ... test using RabbitTemplate etc. } </pre> <p> The
 * rule can be declared as static so that it only has to check once for all tests in the enclosing test case, but there
 * isn't a lot of overhead in making it non-static. </p>
 * 
 * @see Assume
 * @see AssumptionViolatedException
 * 
 * @author Dave Syer
 * 
 */
public class ServerRunning extends TestWatchman {

	private static Log logger = LogFactory.getLog(ServerRunning.class);

	// Static so that we only test once on failure: speeds up test suite
	private static Map<Integer, Boolean> serverOnline = new HashMap<Integer, Boolean>();

	// Static so that we only test once on failure
	private static Map<Integer, Boolean> serverOffline = new HashMap<Integer, Boolean>();

	private final boolean assumeOnline;

	private static int DEFAULT_PORT = 8080;

	private static String DEFAULT_HOST = "localhost";

	private int port;

	private String hostName = DEFAULT_HOST;

	/**
	 * @return a new rule that assumes an existing running broker
	 */
	public static ServerRunning isRunning() {
		return new ServerRunning(true);
	}

	/**
	 * @return a new rule that assumes there is no existing broker
	 */
	public static ServerRunning isNotRunning() {
		return new ServerRunning(false);
	}

	private ServerRunning(boolean assumeOnline) {
		this.assumeOnline = assumeOnline;
		setPort(DEFAULT_PORT);
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
		if (!serverOffline.containsKey(port)) {
			serverOffline.put(port, true);
		}
		if (!serverOnline.containsKey(port)) {
			serverOnline.put(port, true);
		}
	}

	/**
	 * @param hostName the hostName to set
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	@Override
	public Statement apply(Statement base, FrameworkMethod method, Object target) {

		// Check at the beginning, so this can be used as a static field
		if (assumeOnline) {
			Assume.assumeTrue(serverOnline.get(port));
		} else {
			Assume.assumeTrue(serverOffline.get(port));
		}

		RestTemplate client = new RestTemplate();
		HttpURLConnection.setFollowRedirects(false);
		boolean online = false;
		try {
			client.getForEntity(new UriTemplate(getUrl("/sparklr/oauth/user/authorize")).toString(), String.class);
			online = true;
			logger.info("Basic connectivity test passed");
		} catch (RestClientException e) {
			logger.warn("Not executing tests because basic connectivity test failed", e);
			if (assumeOnline) {
				Assume.assumeNoException(e);
			}
		} finally {
			if (online) {
				serverOffline.put(port, false);
				if (!assumeOnline) {
					Assume.assumeTrue(serverOffline.get(port));
				}

			} else {
				serverOnline.put(port, false);
			}
		}

		return super.apply(base, method, target);

	}

	public String getBaseUrl() {
		return "http://" + hostName + ":" + port;
	}

	public String getUrl(String path) {
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		return "http://" + hostName + ":" + port + path;
	}

}
