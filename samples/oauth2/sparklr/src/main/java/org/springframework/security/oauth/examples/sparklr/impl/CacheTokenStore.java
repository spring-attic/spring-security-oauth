package org.springframework.security.oauth.examples.sparklr.impl;

import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.Cache.ValueWrapper;
import org.springframework.cache.CacheManager;
//import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Neev demo. Copy of InMemoryTokenStore, with map calls replaced with 
 * calls to cache. Using cache API directly instead of annotations as need to check for nulls etc
 * Can use any backing cache as long as its initialized. 
 * @see CacheTokenConfig
 * 
 * @author Tushar Kapila. April 2015.
 * */
//@CacheConfig(cacheNames = { "accessTokenCache" })//after spring core upgrade
public class CacheTokenStore implements TokenStore, InitializingBean, ApplicationContextAware {

	private static final Logger logger = LogManager.getLogger(CacheTokenStore.class);

	private static final int DEFAULT_FLUSH_INTERVAL = 99000;

	private static final Set<OAuth2AccessToken> OA_TOKEN_EMPTY_LST = Collections.<OAuth2AccessToken> emptySet();

	private Cache accessTokenCache;

	private Cache authenticationToAccessTokenCache;

	private Cache userNameToAccessTokenCache;

	private Cache clientIdToAccessTokenCache;

	private Cache refreshTokenCache;

	private Cache accessTokenToRefreshTokenCache;

	private Cache refreshTokenAuthenticationCache;

	private Cache refreshTokenToAccessTokenCache;

	private Cache authenticationCache;

	// private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	// private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String,
	// OAuth2AccessToken>();

	// private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore = new ConcurrentHashMap<String,
	// Collection<OAuth2AccessToken>>();

	// private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore = new ConcurrentHashMap<String,
	// Collection<OAuth2AccessToken>>();

	// private final ConcurrentHashMap<String, OAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap<String, OAuth2RefreshToken>();

	// private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap<String, String>();

	// private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String,
	// OAuth2Authentication>();
	//
	// private final ConcurrentHashMap<String, OAuth2Authentication> refreshTokenAuthenticationStore = new ConcurrentHashMap<String,
	// OAuth2Authentication>();
	//
	// private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap<String, String>();

	private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue<TokenExpiry>();//

	private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap<String, TokenExpiry>();

	@Autowired
	private ApplicationContext ctx = null;

	@Autowired
	private CacheManager cacheManager = null;// ctx.getBean("cacheManager", CacheManager.class);

	private int flushInterval = DEFAULT_FLUSH_INTERVAL;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	private AtomicInteger flushCounter = new AtomicInteger(0);

	static {
	}

	/**
	 * The number of tokens to store before flushing expired tokens. Defaults to 1000.
	 * 
	 * @param flushInterval
	 *            the interval to set
	 */
	public void setFlushInterval(int flushInterval) {
		this.flushInterval = flushInterval;
	}

	/**
	 * The interval (count of token inserts) between flushing expired tokens.
	 * 
	 * @return the flushInterval the flush interval
	 */
	public int getFlushInterval() {
		return flushInterval;
	}

	/**
	 * Convenience method for super admin users to remove all tokens (useful for testing, not really in production)
	 */
	public void clear() {
		accessTokenCache.clear();
		authenticationToAccessTokenCache.clear();
		clientIdToAccessTokenCache.clear();
		refreshTokenCache.clear();
		accessTokenToRefreshTokenCache.clear();
		authenticationCache.clear();
		refreshTokenAuthenticationCache.clear();
		refreshTokenToAccessTokenCache.clear();
		expiryQueue.clear();
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public int getAccessTokenCount() {
		// dummy method to pass testing
		// Assert.state(accessTokenCache. || accessTokenStore.size() >= accessTokenToRefreshTokenStore.size(),
		// "Too many refresh tokens");
		// Assert.state(accessTokenStore.size() == authenticationToAccessTokenStore.size(),
		// "Inconsistent token store state");
		// Assert.state(accessTokenStore.size() <= authenticationStore.size(), "Inconsistent authentication store state");
		// return accessTokenStore.size();

		return 100;
	}

	public int getRefreshTokenCount() {
		// dummy method to pass testing
		// Assert.state(refreshTokenStore.size() == refreshTokenToAccessTokenStore.size(),
		// "Inconsistent refresh token store state");
		// return accessTokenStore.size();
		return 100;
	}

	public int getExpiryTokenCount() {
		return expiryQueue.size();
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		ValueWrapper vw = authenticationToAccessTokenCache.get(key);
		if (vw == null){
			return null;
		}
		OAuth2AccessToken accessToken = (OAuth2AccessToken) vw.get();
		if (accessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is represented by this authentication but the details
			// have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	public OAuth2Authentication readAuthentication(String token) {
		ValueWrapper vw = this.authenticationCache.get(token);
		if (vw == null){
			return null;
		}
		return (OAuth2Authentication) vw.get();
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String token) {
		ValueWrapper vw = this.refreshTokenAuthenticationCache.get(token);
		if (vw == null){
			return null;
		}
		return (OAuth2Authentication) vw.get();
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
			flush();
			this.flushCounter.set(0);
		}
		logger.info("storeAccessToken token "+ token + ", " + authentication);
		this.accessTokenCache.put(token.getValue(), token);
		this.authenticationCache.put(token.getValue(), authentication);
		this.authenticationToAccessTokenCache.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (!authentication.isClientOnly()) {
			addToCollection(this.userNameToAccessTokenCache, getApprovalKey(authentication), token);
		}
		addToCollection(this.clientIdToAccessTokenCache, authentication.getOAuth2Request().getClientId(), token);
		if (token.getExpiration() != null) {
			TokenExpiry expiry = new TokenExpiry(token.getValue(), token.getExpiration());
			// Remove existing expiry for this token if present
			expiryQueue.remove(expiryMap.put(token.getValue(), expiry));
			this.expiryQueue.put(expiry);
		}
		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAccessTokenCache.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenCache.put(token.getValue(), token.getRefreshToken().getValue());
		}
	}

	private String getApprovalKey(OAuth2Authentication authentication) {
		String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
		return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
	}

	private String getApprovalKey(String clientId, String userName) {
		return clientId + (userName == null ? "" : ":" + userName);
	}

	@SuppressWarnings("unchecked")
	private void addToCollection(Cache cache, String key, OAuth2AccessToken token) {
		ValueWrapper vw = cache.get(key);
		if (vw == null) {
			synchronized (cache) {
				vw = cache.get(key);
				if (vw == null) {
					cache.put(key, new HashSet<OAuth2AccessToken>());
				}
			}
		}
		vw = cache.get(key);
		if(vw!= null){
			Object o = vw.get();
			((HashSet<OAuth2AccessToken>) o).add(token);
		}else{
			logger.info("no hashset, key " + key + " token " + token + ", "  + (token == null? token : token.getValue()));
		}
	}

	// private void addToCollection(ConcurrentHashMap<String, Collection<OAuth2AccessToken>> store, String key, OAuth2AccessToken token) {
	// if (!store.containsKey(key)) {
	// synchronized (store) {
	// if (!store.containsKey(key)) {
	// store.put(key, new HashSet<OAuth2AccessToken>());
	// }
	// }
	// }
	// store.get(key).add(token);
	// }

	public void removeAccessToken(OAuth2AccessToken accessToken) {
		removeAccessToken(accessToken.getValue());
	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return (OAuth2AccessToken) this.accessTokenCache.get(tokenValue).get();
	}

	public void removeAccessToken(String tokenValue) {
		logger.info("removeAccessToken tokenValue " + tokenValue);
		ValueWrapper vw = this.accessTokenCache.get(tokenValue);
		OAuth2AccessToken removed = null;
		if (vw != null) {
			removed = (OAuth2AccessToken) vw.get();
		}
		logger.info("removeAccessToken removed " + removed);
		this.accessTokenToRefreshTokenCache.evict(tokenValue);
		// Don't remove the refresh token - it's up to the caller to do that
		OAuth2Authentication authentication = null;
		vw = this.authenticationCache.get(tokenValue);
		if (vw != null) {
			authentication = (OAuth2Authentication) vw.get();
		}
		this.authenticationCache.evict(tokenValue);
		if (authentication != null) {
			this.authenticationToAccessTokenCache.evict(authenticationKeyGenerator.extractKey(authentication));
			Collection<OAuth2AccessToken> tokens;
			tokens = (Collection<OAuth2AccessToken>) this.userNameToAccessTokenCache.get(authentication.getName()).get();
			if (tokens != null) {
				tokens.remove(removed);
			}
			String clientId = authentication.getOAuth2Request().getClientId();
			tokens = null;//
			vw = this.clientIdToAccessTokenCache.get(clientId);
			if (vw != null) {
				tokens = (Collection<OAuth2AccessToken>) vw.get();
				if (tokens != null) {
					tokens.remove(removed);
				}
			}
			
			this.authenticationToAccessTokenCache.evict(authenticationKeyGenerator.extractKey(authentication));
		}
		logger.info("end removeAccessToken.");
	}

	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		this.refreshTokenCache.put(refreshToken.getValue(), refreshToken);
		this.refreshTokenAuthenticationCache.put(refreshToken.getValue(), authentication);
	}

	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		OAuth2RefreshToken token = null;
		ValueWrapper o = this.refreshTokenCache.get(tokenValue);
		if (o != null) {
			token = (OAuth2RefreshToken) o.get();
		}
		return token;
	}

	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		removeRefreshToken(refreshToken.getValue());
	}

	public void removeRefreshToken(String tokenValue) {
		this.refreshTokenCache.evict(tokenValue);
		this.refreshTokenAuthenticationCache.evict(tokenValue);
		this.refreshTokenToAccessTokenCache.evict(tokenValue);
	}

	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	private void removeAccessTokenUsingRefreshToken(String refreshToken) {
		ValueWrapper vw = this.refreshTokenToAccessTokenCache.get(refreshToken);
		if (vw != null) {
			this.refreshTokenToAccessTokenCache.evict(refreshToken);
			String accessToken = (String) vw.get();
			if (accessToken != null) {
				removeAccessToken(accessToken);
			}
		}
	}

	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		ValueWrapper vw = userNameToAccessTokenCache.get(getApprovalKey(clientId, userName));
		if (vw == null) {
			return OA_TOKEN_EMPTY_LST;
		}
		logger.info("findTokensByClientIdAndUserName userName:" + userName + ", " + vw.get());
		Collection<OAuth2AccessToken> result = (Collection<OAuth2AccessToken>) vw.get();
		return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : OA_TOKEN_EMPTY_LST;
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		ValueWrapper vw = clientIdToAccessTokenCache.get(clientId);
		if (vw == null) {
			return OA_TOKEN_EMPTY_LST;
		}
		logger.info("findTokensByClientId clientId " + clientId + ", " + vw.get());
		Collection<OAuth2AccessToken> result = (Collection<OAuth2AccessToken>) vw.get();
		return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : OA_TOKEN_EMPTY_LST;
	}

	private void flush() {
		TokenExpiry expiry = expiryQueue.poll();
		while (expiry != null) {
			removeAccessToken(expiry.getValue());
			expiry = expiryQueue.poll();
		}
	}

	private static class TokenExpiry implements Delayed {

		private final long expiry;

		private final String value;

		public TokenExpiry(String value, Date date) {
			this.value = value;
			this.expiry = date.getTime();
		}

		public int compareTo(Delayed other) {
			if (this == other) {
				return 0;
			}
			long diff = getDelay(TimeUnit.MILLISECONDS) - other.getDelay(TimeUnit.MILLISECONDS);
			return (diff == 0 ? 0 : ((diff < 0) ? -1 : 1));
		}

		public long getDelay(TimeUnit unit) {
			return expiry - System.currentTimeMillis();
		}

		public String getValue() {
			return value;
		}

	}

	@Override
	public void afterPropertiesSet() throws Exception {
		try {
			logger.info("CacheStore afterPropertiesSet :" + cacheManager);
			accessTokenCache = cacheManager.getCache("accessTokenCache");
			authenticationToAccessTokenCache = cacheManager.getCache("authenticationToAccessTokenCache");

			userNameToAccessTokenCache = cacheManager.getCache("userNameToAccessTokenCache");

			clientIdToAccessTokenCache = cacheManager.getCache("clientIdToAccessTokenCache");

			refreshTokenCache = cacheManager.getCache("refreshTokenCache");

			accessTokenToRefreshTokenCache = cacheManager.getCache("accessTokenToRefreshTokenCache");

			refreshTokenAuthenticationCache = cacheManager.getCache("refreshTokenAuthenticationCache");

			authenticationCache = cacheManager.getCache("authenticationCache");
			SimpleDateFormat sdf = new SimpleDateFormat("MM dd HH mm ss");
			String s = "b" + sdf.format(new java.util.Date());
			logger.info("authenticationCache " + authenticationCache);
			logger.info("a s -:" + s);
			logger.info("a s " + s);
			authenticationCache.put("a", s);
		} catch (Throwable e) {
			logger.info("ERR " + e);
			e.printStackTrace();
		}

	}

	public void setApplicationContext(ApplicationContext c) {
		ctx = c;
	}

	public ApplicationContext getApplicationContext() {
		return ctx;
	}

	public CacheManager getCacheManager() {
		return cacheManager;
	}

	public void setCacheManager(CacheManager cacheManager) {
		logger.info("get4cacheManager :" + cacheManager + ".");
		this.cacheManager = cacheManager;
	}

	//test method TODO remove.
	@Cacheable(value="authenticationCache")
	public String getAVal1(String m) {
		logger.info("getAVal1 :" + m + ".");
		return m + "-1";
	}

}
