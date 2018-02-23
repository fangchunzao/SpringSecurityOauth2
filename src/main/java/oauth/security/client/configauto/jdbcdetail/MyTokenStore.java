package oauth.security.client.configauto.jdbcdetail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

public class MyTokenStore {

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    public MyTokenStore() {

    }

    public TokenStore getTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

}
