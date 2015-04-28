package org.springframework.security.oauth.examples.sparklr.config;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.redis.cache.DefaultRedisCachePrefix;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.cache.RedisCachePrefix;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth.examples.sparklr.impl.CacheTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * Neev demo. Initializes cache config. Options - see cache.properties.
 * 
 * @author Tushar Kapila. April 2015.
 * */
@Configuration
@PropertySource("classpath:/cache.properties")
public class CacheTokenConfig implements InitializingBean {
	private static final Logger logger = LogManager.getLogger(CacheTokenConfig.class);
	public static final String CACHE_NAME = "_oauth_";

	public static final String[] CACHE_NAMES = new String[] { "accessTokenCache", "authenticationToAccessTokenCache",
			"userNameToAccessTokenCache", "clientIdToAccessTokenCache", "refreshTokenCache", "accessTokenToRefreshTokenCache",
			"refreshTokenAuthenticationCache", "authenticationCache" };

	private @Value("${redis.host-name}") String redisHostName;
	private @Value("${redis.port}") int redisPort;

	/*** Full class name or 1 (default) : in memory, 2 redis */
	private @Value("${cache.use}") String cacheToUse = "1";

	/** 1 InMemory, 2 : cache **/
	private @Value("${store.use}") String storeToUse = "1";

	private TokenStore tokenStore;

	@Bean
	JedisConnectionFactory jedisConnectionFactory() {
		JedisConnectionFactory factory = new JedisConnectionFactory();
		factory.setHostName(redisHostName);
		factory.setPort(redisPort);
		factory.setUsePool(true);
		return factory;
	}

	@Bean
	RedisTemplate<Object, Object> redisTemplate() {
		RedisTemplate<Object, Object> redisTemplate = new RedisTemplate<Object, Object>();
		redisTemplate.setConnectionFactory(jedisConnectionFactory());
		return redisTemplate;
	}

	@Bean
	CacheManager createSimpleCacheManager() {
		CacheManager cm = null;
		logger.info("Cache to use :" + cacheToUse);
		if ("2".equals(cacheToUse)) {
			RedisCacheManager rcm = new RedisCacheManager(redisTemplate());
			// rcm.setDefaultExpiration(999999);
			boolean usePrefixes = true;
			rcm.setUsePrefix(usePrefixes);
			if (usePrefixes) {
				// seperator
				RedisCachePrefix cachePrefix = new DefaultRedisCachePrefix("-" + OAuth2ServerConfig.SPARKLR_RESOURCE_ID + "-");
				rcm.setCachePrefix(cachePrefix);
				logger.info("Cac ore :" + cachePrefix.prefix(CACHE_NAME));
			}
			//might not need this in spring 4
			for (int i = 0; i < CACHE_NAMES.length; i++) {
				Cache ca = rcm.getCache(CACHE_NAMES[i]);
				logger.info(i + CACHE_NAMES[i] + " " + ca);
			}
			cm = rcm;
		} else if ("1".equals(cacheToUse)) {
			// do below in default
			logger.info("-default below- :");
		} else {
			try {
				cm = (CacheManager) Class.forName(cacheToUse).newInstance();
			} catch (Throwable e) {
				logger.info("ERR cacheManager :" + e);
			}
		}
		if (cm == null) {
			SimpleCacheManager scm = new SimpleCacheManager();
			Collection<Cache> caches = new ArrayList<>();
			for (int i = 0; i < CACHE_NAMES.length; i++) {
				ConcurrentMapCache cmc = new ConcurrentMapCache(CACHE_NAMES[i]);
				caches.add(cmc);
			}
			scm.setCaches(caches);
			cm = scm;
		}
		logger.info("-CacheManager- :" + cm);
		return cm;
	}

	@Bean
	public TokenStore tokenStore() {
		if (tokenStore == null) {
			if ("1".equals(storeToUse)) {
				tokenStore = new InMemoryTokenStore();// std spring
			} else if ("2".equals(storeToUse)) {
				tokenStore = new CacheTokenStore();
			} else {
				try {
					tokenStore = (TokenStore) Class.forName(storeToUse).newInstance();
				} catch (Throwable e) {
					logger.info("ERR :" + e + "cache use :" + cacheToUse + " " + tokenStore);
				}
			}
			logger.info("Token use :" + storeToUse + " " + tokenStore);
		}
		return tokenStore;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		logger.info("CacheConfig redisHost -:" + redisHostName + ":" + redisPort);

	}
}
