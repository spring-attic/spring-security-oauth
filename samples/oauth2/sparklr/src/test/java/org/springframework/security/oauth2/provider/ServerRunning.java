package org.springframework.security.oauth2.provider;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;

/**
 * <p>
 * A rule that prevents integration tests from failing if the server application is not running or not accessible. If
 * the server is not running in the background all the tests here will simply be skipped because of a violated
 * assumption (showing as successful). Usage:
 * </p>
 * 
 * <pre>
 * &#064;Rule public static BrokerRunning brokerIsRunning = BrokerRunning.isRunning();
 * 
 * &#064;Test public void testSendAndReceive() throws Exception { // ... test using RabbitTemplate etc. }
 * </pre>
 * <p>
 * The rule can be declared as static so that it only has to check once for all tests in the enclosing test case, but
 * there isn't a lot of overhead in making it non-static.
 * </p>
 * 
 * @see Assume
 * @see AssumptionViolatedException
 * 
 * @author Dave Syer
 * 
 */
public class ServerRunning implements MethodRule, RestTemplateHolder {

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

	private RestOperations client;
	
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
		client = createRestTemplate();
	}

	/**
	 * @param hostName the hostName to set
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public Statement apply(final Statement base, FrameworkMethod method, Object target) {

		// Check at the beginning, so this can be used as a static field
		if (assumeOnline) {
			Assume.assumeTrue(serverOnline.get(port));
		}
		else {
			Assume.assumeTrue(serverOffline.get(port));
		}

		RestTemplate client = new RestTemplate();
		boolean followRedirects = HttpURLConnection.getFollowRedirects();
		HttpURLConnection.setFollowRedirects(false);
		boolean online = false;
		try {
			client.getForEntity(new UriTemplate(getUrl("/sparklr2/login.jsp")).toString(), String.class);
			online = true;
			logger.info("Basic connectivity test passed");
		}
		catch (RestClientException e) {
			logger.warn(String.format(
					"Not executing tests because basic connectivity test failed for hostName=%s, port=%d", hostName,
					port), e);
			if (assumeOnline) {
				Assume.assumeNoException(e);
			}
		}
		finally {
			HttpURLConnection.setFollowRedirects(followRedirects);
			if (online) {
				serverOffline.put(port, false);
				if (!assumeOnline) {
					Assume.assumeTrue(serverOffline.get(port));
				}

			}
			else {
				serverOnline.put(port, false);
			}
		}

		final RestOperations savedClient = getRestTemplate();
		postForStatus(savedClient, "/sparklr2/oauth/uncache_approvals",
				new LinkedMultiValueMap<String, String>());

		return new Statement() {

			@Override
			public void evaluate() throws Throwable {
				try {
					base.evaluate();
				}
				finally {
					postForStatus(savedClient, "/sparklr2/oauth/cache_approvals",
							new LinkedMultiValueMap<String, String>());
				}

			}
		};

	}
	
	public String getBaseUrl() {
		return "http://" + hostName + ":" + port;
	}

	public String getUrl(String path) {
		if (path.startsWith("http")) {
			return path;
		}
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		return "http://" + hostName + ":" + port + path;
	}

	public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), String.class);
	}

	public ResponseEntity<String> postForString(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				actualHeaders), String.class);
	}

	@SuppressWarnings("rawtypes")
	public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData) {
		return postForMap(path, new HttpHeaders(), formData);
	}

	@SuppressWarnings("rawtypes")
	public ResponseEntity<Map> postForMap(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), Map.class);
	}

	public ResponseEntity<Void> postForStatus(String path, MultiValueMap<String, String> formData) {
		return postForStatus(this.client, path, formData);
	}

	public ResponseEntity<Void> postForStatus(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		return postForStatus(this.client, path, headers, formData);
	}

	private ResponseEntity<Void> postForStatus(RestOperations client, String path,
			MultiValueMap<String, String> formData) {
		return postForStatus(client, path, new HttpHeaders(), formData);
	}

	private ResponseEntity<Void> postForStatus(RestOperations client, String path, HttpHeaders headers,
			MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				actualHeaders), (Class<Void>)null);
	}

	public ResponseEntity<Void> postForRedirect(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
		ResponseEntity<Void> exchange = postForStatus(path, headers, params);

		if (exchange.getStatusCode() != HttpStatus.FOUND) {
			throw new IllegalStateException("Expected 302 but server returned status code " + exchange.getStatusCode());
		}

		if (exchange.getHeaders().containsKey("Set-Cookie")) {
			String cookie = exchange.getHeaders().getFirst("Set-Cookie");
			headers.set("Cookie", cookie);
		}

		String location = exchange.getHeaders().getLocation().toString();

		return client.exchange(location, HttpMethod.GET, new HttpEntity<Void>(null, headers), (Class<Void>)null);
	}

	public ResponseEntity<String> getForString(String path) {
		return getForString(path, new HttpHeaders());
	}

	public ResponseEntity<String> getForString(String path, final HttpHeaders headers) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null, headers), String.class);
	}

	public ResponseEntity<String> getForString(String path, final HttpHeaders headers, Map<String, String> uriVariables) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null, headers), String.class,
				uriVariables);
	}

	public ResponseEntity<Void> getForResponse(String path, final HttpHeaders headers, Map<String, String> uriVariables) {
		HttpEntity<Void> request = new HttpEntity<Void>(null, headers);
		return client.exchange(getUrl(path), HttpMethod.GET, request, (Class<Void>)null, uriVariables);
	}

	public ResponseEntity<Void> getForResponse(String path, HttpHeaders headers) {
		return getForResponse(path, headers, Collections.<String, String> emptyMap());
	}

	public HttpStatus getStatusCode(String path, final HttpHeaders headers) {
		ResponseEntity<Void> response = getForResponse(path, headers);
		return response.getStatusCode();
	}

	public HttpStatus getStatusCode(String path) {
		return getStatusCode(getUrl(path), null);
	}

	public void setRestTemplate(RestOperations restTemplate) {
		client = restTemplate;
	}

	public RestOperations getRestTemplate() {
		return client;
	}
	
	public RestOperations createRestTemplate() {
		RestTemplate client = new RestTemplate();
		client.setRequestFactory(new HttpComponentsClientHttpRequestFactory() {
			@Override
			public HttpClient getHttpClient() {
				HttpClient client = super.getHttpClient();
				client.getParams().setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, false);
				client.getParams().setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.IGNORE_COOKIES);
				client.getParams().setBooleanParameter(ClientPNames.HANDLE_AUTHENTICATION, false);
				return client;
			}
		});
		client.setErrorHandler(new ResponseErrorHandler() {
			// Pass errors through in response entity for status code analysis
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}

			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});
		return client;
	}

	public UriBuilder buildUri(String url) {
		return UriBuilder.fromUri(url.startsWith("http:") ? url : getUrl(url));
	}

	public static class UriBuilder {

		private final String url;

		private Map<String, String> params = new LinkedHashMap<String, String>();

		public UriBuilder(String url) {
			this.url = url;
		}

		public static UriBuilder fromUri(String url) {
			return new UriBuilder(url);
		}

		public UriBuilder queryParam(String key, String value) {
			params.put(key, value);
			return this;
		}

		public String pattern() {
			StringBuilder builder = new StringBuilder();
			// try {
			builder.append(url.replace(" ", "+"));
			if (!params.isEmpty()) {
				builder.append("?");
				boolean first = true;
				for (String key : params.keySet()) {
					if (!first) {
						builder.append("&");
					}
					else {
						first = false;
					}
					String value = params.get(key);
					if (value.contains("=")) {
						value = value.replace("=", "%3D");
					}
					builder.append(key + "={" + key + "}");
				}
			}
			return builder.toString();

		}

		public Map<String, String> params() {
			return params;
		}

		public URI build() {
			return new UriTemplate(pattern()).expand(params);
		}
	}

}
