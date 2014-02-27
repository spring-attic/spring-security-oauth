package org.springframework.security.oauth.examples.tonr;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;
import org.springframework.web.util.UriUtils;

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
public class ServerRunning implements MethodRule {

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

	private RestTemplate client;

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
		client = getRestTemplate();
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
		} else {
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
		} catch (RestClientException e) {
			logger.warn(String.format(
					"Not executing tests because basic connectivity test failed for hostName=%s, port=%d", hostName,
					port), e);
			if (assumeOnline) {
				Assume.assumeNoException(e);
			}
		} finally {
			HttpURLConnection.setFollowRedirects(followRedirects);
			if (online) {
				serverOffline.put(port, false);
				if (!assumeOnline) {
					Assume.assumeTrue(serverOffline.get(port));
				}

			} else {
				serverOnline.put(port, false);
			}
		}

		return new Statement() {

			@Override
			public void evaluate() throws Throwable {
				try {
					postForStatus("/sparklr2/oauth/uncache_approvals", new LinkedMultiValueMap<String, String>());
					base.evaluate();
				} finally {
					postForStatus("/sparklr2/oauth/cache_approvals", new LinkedMultiValueMap<String, String>());
				}

			}
		};

	}

	public String getBaseUrl() {
		return "http://" + hostName + ":" + port;
	}

	public String getUrl(String path) {
		if (path.startsWith("http:")) {
			return path;
		}
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		return "http://" + hostName + ":" + port + path;
	}

	public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), String.class);
	}

	public ResponseEntity<Void> postForStatus(String path, MultiValueMap<String, String> formData) {
		return postForStatus(path, new HttpHeaders(), formData);
	}

	public ResponseEntity<Void> postForStatus(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				actualHeaders), (Class<Void>)null);
	}

	public HttpHeaders postForHeaders(String path, MultiValueMap<String, String> formData) {
		return postForHeaders(path, formData, null);
	}

	public HttpHeaders postForHeaders(String path, MultiValueMap<String, String> formData, final HttpHeaders headers) {

		RequestCallback requestCallback = new NullRequestCallback();
		if (headers != null) {
			requestCallback = new RequestCallback() {
				public void doWithRequest(ClientHttpRequest request) throws IOException {
					request.getHeaders().putAll(headers);
				}
			};
		}

		StringBuilder builder = new StringBuilder(getUrl(path));
		if (!path.contains("?")) {
			builder.append("?");
		} else {
			builder.append("&");
		}
		for (String key : formData.keySet()) {
			for (String value : formData.get(key)) {
				builder.append(key + "=" + value);
				builder.append("&");
			}
		}
		builder.deleteCharAt(builder.length() - 1);
		return client.execute(builder.toString(), HttpMethod.POST, requestCallback,
				new ResponseExtractor<HttpHeaders>() {
					public HttpHeaders extractData(ClientHttpResponse response) throws IOException {
						return response.getHeaders();
					}
				});
	}

	public ResponseEntity<String> postForString(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), String.class);
	}

	public ResponseEntity<String> getForString(String path, final HttpHeaders headers) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null, headers), String.class);
	}

	public ResponseEntity<String> getForString(String path) {
		return getForString(path, new HttpHeaders());
	}

	public String getForRedirect(String path, final HttpHeaders headers) {
		ResponseEntity<Void> response = client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null,
				headers), Void.class);
		URI location = response.getHeaders().getLocation();
		try {
			return URLDecoder.decode(location.toString(), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Could not decode URL", e);
		}
	}

	public HttpStatus getStatusCode(String path, final HttpHeaders headers) {
		RequestCallback requestCallback = new NullRequestCallback();
		if (headers != null) {
			requestCallback = new RequestCallback() {
				public void doWithRequest(ClientHttpRequest request) throws IOException {
					request.getHeaders().putAll(headers);
				}
			};
		}
		return client.execute(getUrl(path), HttpMethod.GET, requestCallback,
				new ResponseExtractor<ResponseEntity<Void>>() {
					public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
						FileCopyUtils.copyToByteArray(response.getBody());
						return new ResponseEntity<Void>(response.getStatusCode());
					}
				}).getStatusCode();
	}

	public HttpStatus getStatusCode(String path) {
		return getStatusCode(getUrl(path), null);
	}

	public RestTemplate getRestTemplate() {
		RestTemplate client = new RestTemplate();
		client.setRequestFactory(new SimpleClientHttpRequestFactory() {
			@Override
			protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
				super.prepareConnection(connection, httpMethod);
				connection.setInstanceFollowRedirects(false);
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

	private static final class NullRequestCallback implements RequestCallback {
		public void doWithRequest(ClientHttpRequest request) throws IOException {
		}
	}

	public static class UriBuilder {

		private final String url;
		private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

		public UriBuilder(String url) {
			this.url = url;
		}

		public static UriBuilder fromUri(String url) {
			return new UriBuilder(url);
		}

		public UriBuilder queryParam(String key, String value) {
			params.add(key, value);
			return this;
		}

		public URI build() {
			StringBuilder builder = new StringBuilder(url);
			try {
				if (!params.isEmpty()) {
					builder.append("?");
					boolean first = true;
					for (String key : params.keySet()) {
						if (!first) {
							builder.append("&");
						} else {
							first = false;
						}
						for (String value : params.get(key)) {
							builder.append(key + "=" + UriUtils.encodeQueryParam(value, "UTF-8"));
						}
					}
				}
				return new URI(builder.toString());
			} catch (UnsupportedEncodingException ex) {
				// should not happen, UTF-8 is always supported
				throw new IllegalStateException(ex);
			} catch (URISyntaxException ex) {
				throw new IllegalArgumentException("Could not create URI from [" + builder + "]: " + ex, ex);
			}
		}

	}

}
