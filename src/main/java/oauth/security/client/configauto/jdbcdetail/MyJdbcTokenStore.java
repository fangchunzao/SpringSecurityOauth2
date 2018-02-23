package oauth.security.client.configauto.jdbcdetail;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

/**
 *  自定义 jdbc TokenStore
 */
public class MyJdbcTokenStore implements TokenStore {
    private static final Log LOG = LogFactory.getLog(MyJdbcTokenStore.class);
    private String updateAccessTokenSql = "update authentication a set a.token_id = ?,a.token = ?,a.token_byte = ?, a.authentication_id = ?, a.authentication = ?, a.refresh_token = ? where id = ?";
    private String selectExistClientFromClientNameSql = "select id from authentication where client_name = ? limit 1";
    private String selectAccessTokenSql = "select token_id, token_byte from authentication where token_id = ?";
    private String selectAccessTokenAuthenticationSql = "select token_id, authentication from authentication where token_id = ?";
    private String selectAccessTokenFromAuthenticationSql = "select token_id, token_byte from authentication where authentication_id = ?";
    // 下面SQL的没啥用
    private String selectAccessTokensFromClientIdSql = "select token_id, token from authentication where client_id = ?";
    private String deleteAccessTokenSql = "delete from authentication where token_id = ?";

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
    private final JdbcTemplate jdbcTemplate;

    public MyJdbcTokenStore(DataSource dataSource) {
        Assert.notNull(dataSource, "DataSource required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    /**
     * 判断token状态 获取token
     * @param authentication
     * @return
     */
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;
        String key = this.authenticationKeyGenerator.extractKey(authentication);  //authentication_id

        //通过 authentication_id 查询
        try {
            accessToken = (OAuth2AccessToken)this.jdbcTemplate.queryForObject(this.selectAccessTokenFromAuthenticationSql, new RowMapper<OAuth2AccessToken>() {
                public OAuth2AccessToken mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return MyJdbcTokenStore.this.deserializeAccessToken(rs.getBytes(2));
                }
            }, new Object[]{key});
        } catch (EmptyResultDataAccessException var5) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for authentication " + authentication);
            }
        } catch (IllegalArgumentException var6) {
            LOG.error("Could not extract access token for authentication " + authentication, var6);
        }

        if (accessToken != null && !key.equals(this.authenticationKeyGenerator.extractKey(this.readAuthentication(accessToken.getValue())))) {
            this.storeAccessToken(accessToken, authentication);
        }

        return accessToken;
    }

    /**
     * token 更新
     * @param authentication
     * @return
     */
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        String refreshToken = null;
        String clientNameParam = authentication.getOAuth2Request().getClientId();  // 请求应用名称
        String clientNameRes = null;

        if (token.getRefreshToken() != null) {
            refreshToken = token.getRefreshToken().getValue();
        }

        if (this.readAccessToken(token.getValue()) != null) {     // 如果token已经存在
            this.removeAccessToken(token.getValue());
        }

        // 通过ClientName 查询当前应用ID
        try {
            clientNameRes = this.jdbcTemplate.queryForObject(this.selectExistClientFromClientNameSql, new RowMapper<String>() {
                public String mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return rs.getString(1);
                }
            } , new Object[]{clientNameParam});
        } catch (EmptyResultDataAccessException var5) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for ClientName " + clientNameParam);
            }
        } catch (IllegalArgumentException var6) {
            LOG.error("Could not extract access token for ClientName " + clientNameParam, var6);
        }

        if(clientNameRes == null) {
            throw new ClientRegistrationException("该应用不存在!");
        }

        String tokenValue = token.getValue(); // token 值

        // 更新当前clientId 的token信息
        this.jdbcTemplate.update(this.updateAccessTokenSql,
                new Object[]{this.extractTokenKey(token.getValue()), tokenValue, new SqlLobValue(this.serializeAccessToken(token))
                        , this.authenticationKeyGenerator.extractKey(authentication), new SqlLobValue(this.serializeAuthentication(authentication))
                        , this.extractTokenKey(refreshToken), clientNameRes}, new int[]{12, 12, 2004, 12, 2004, 12, 12});
    }

    /**
     *  验证token 合法
     * @param tokenValue token
     * @return
     */
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessToken accessToken = null;
        String tokenId = this.extractTokenKey(tokenValue);
        try {
            // 使用token_id 查询 如果存在说明token已经存在
             accessToken = (OAuth2AccessToken)this.jdbcTemplate.queryForObject(this.selectAccessTokenSql, new RowMapper<OAuth2AccessToken>() {
               public OAuth2AccessToken mapRow(ResultSet rs, int rowNum) throws SQLException {
                   return MyJdbcTokenStore.this.deserializeAccessToken(rs.getBytes(2));
                }
            }, new Object[]{this.extractTokenKey(tokenValue)});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + tokenValue);
            }
        } catch (IllegalArgumentException var5) {
            LOG.warn("Failed to deserialize access token for " + tokenValue, var5);
            this.removeAccessToken(tokenValue);
        }

        return accessToken;
    }

    public void removeAccessToken(OAuth2AccessToken token) {
        //this.removeAccessToken(token.getValue());
    }

    public void removeAccessToken(String tokenValue) {
        //this.jdbcTemplate.update(this.deleteAccessTokenSql, new Object[]{this.extractTokenKey(tokenValue)});
    }

    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return this.readAuthentication(token.getValue());
    }

    public OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication authentication = null;
        String tokenId = this.extractTokenKey(token);

        try {
            authentication = (OAuth2Authentication)this.jdbcTemplate.queryForObject(this.selectAccessTokenAuthenticationSql, new RowMapper<OAuth2Authentication>() {
                public OAuth2Authentication mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return MyJdbcTokenStore.this.deserializeAuthentication(rs.getBytes(2));
                }
            }, new Object[]{this.extractTokenKey(token)});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + token);
            }
        } catch (IllegalArgumentException var5) {
            LOG.warn("Failed to deserialize authentication for " + token, var5);
            //this.removeAccessToken(token);
        }

        return authentication;
    }

    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        //this.jdbcTemplate.update(this.insertRefreshTokenSql, new Object[]{this.extractTokenKey(refreshToken.getValue()), new SqlLobValue(this.serializeRefreshToken(refreshToken)), new SqlLobValue(this.serializeAuthentication(authentication))}, new int[]{12, 2004, 2004});
    }

    public OAuth2RefreshToken readRefreshToken(String token) {
        OAuth2RefreshToken refreshToken = null;

/*        try {
            refreshToken = (OAuth2RefreshToken)this.jdbcTemplate.queryForObject(this.selectRefreshTokenSql, new RowMapper<OAuth2RefreshToken>() {
                public OAuth2RefreshToken mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return MyJdbcTokenStore.this.deserializeRefreshToken(rs.getBytes(2));
                }
            }, new Object[]{this.extractTokenKey(token)});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find refresh token for token " + token);
            }
        } catch (IllegalArgumentException var5) {
            LOG.warn("Failed to deserialize refresh token for token " + token, var5);
            this.removeRefreshToken(token);
        }*/

        return refreshToken;
    }

    public void removeRefreshToken(OAuth2RefreshToken token) {
        //this.removeRefreshToken(token.getValue());
    }

    public void removeRefreshToken(String token) {
        //this.jdbcTemplate.update(this.deleteRefreshTokenSql, new Object[]{this.extractTokenKey(token)});
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        return this.readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
        OAuth2Authentication authentication = null;

        /*try {
            authentication = (OAuth2Authentication)this.jdbcTemplate.queryForObject(this.selectRefreshTokenAuthenticationSql, new RowMapper<OAuth2Authentication>() {
                public OAuth2Authentication mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return MyJdbcTokenStore.this.deserializeAuthentication(rs.getBytes(2));
                }
            }, new Object[]{this.extractTokenKey(value)});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + value);
            }
        } catch (IllegalArgumentException var5) {
            LOG.warn("Failed to deserialize access token for " + value, var5);
            this.removeRefreshToken(value);
        }*/

        return authentication;
    }

    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        //this.removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    public void removeAccessTokenUsingRefreshToken(String refreshToken) {
        //this.jdbcTemplate.update(this.deleteAccessTokenFromRefreshTokenSql, new Object[]{this.extractTokenKey(refreshToken)}, new int[]{12});
    }

    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        Object accessTokens = new ArrayList();

        try {
            accessTokens = this.jdbcTemplate.query(this.selectAccessTokensFromClientIdSql, new MyJdbcTokenStore.SafeAccessTokenRowMapper(), new Object[]{clientId});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId);
            }
        }

        List<OAuth2AccessToken> accessTokensRes = this.removeNulls((List)accessTokens);
        return accessTokensRes;
    }

    public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        Object accessTokens = new ArrayList();

        try {
            //accessTokens = this.jdbcTemplate.query(this.selectAccessTokensFromUserNameSql, new MyJdbcTokenStore.SafeAccessTokenRowMapper(), new Object[]{userName});
        } catch (EmptyResultDataAccessException var4) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for userName " + userName);
            }
        }

        List<OAuth2AccessToken> accessTokensRes = this.removeNulls((List)accessTokens);
        return accessTokensRes;
    }

    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        Object accessTokens = new ArrayList();

        try {
//            accessTokens = this.jdbcTemplate.query(this.selectAccessTokensFromUserNameAndClientIdSql, new MyJdbcTokenStore.SafeAccessTokenRowMapper(), new Object[]{userName, clientId});
        } catch (EmptyResultDataAccessException var5) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId + " and userName " + userName);
            }
        }

        List<OAuth2AccessToken> accessTokensRes = this.removeNulls((List)accessTokens);
        return accessTokensRes;
    }

    private List<OAuth2AccessToken> removeNulls(List<OAuth2AccessToken> accessTokens) {
        List<OAuth2AccessToken> tokens = new ArrayList();
        Iterator var3 = accessTokens.iterator();

        while(var3.hasNext()) {
            OAuth2AccessToken token = (OAuth2AccessToken)var3.next();
            if (token != null) {
                tokens.add(token);
            }
        }

        return tokens;
    }

    protected String extractTokenKey(String value) {
        if (value == null) {
            return null;
        } else {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException var5) {
                throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
            }

            try {
                byte[] bytes = digest.digest(value.getBytes("UTF-8"));
                return String.format("%032x", new BigInteger(1, bytes));
            } catch (UnsupportedEncodingException var4) {
                throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
            }
        }
    }

    protected byte[] serializeAccessToken(OAuth2AccessToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
        return SerializationUtils.serialize(authentication);
    }

    protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
        return (OAuth2AccessToken)SerializationUtils.deserialize(token);
    }

    protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
        return (OAuth2RefreshToken)SerializationUtils.deserialize(token);
    }

    protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
        return (OAuth2Authentication)SerializationUtils.deserialize(authentication);
    }

    public void setSelectAccessTokenSql(String selectAccessTokenSql) {
        this.selectAccessTokenSql = selectAccessTokenSql;
    }

    public void setSelectExistClientFromClientNameSql(String selectExistClientFromClientNameSql) {
        this.selectExistClientFromClientNameSql = selectExistClientFromClientNameSql;
    }

    public void setUpdateAccessTokenSql(String updateAccessTokenSql) {
        this.updateAccessTokenSql = updateAccessTokenSql;
    }

    public void setDeleteAccessTokenSql(String deleteAccessTokenSql) {
        this.deleteAccessTokenSql = deleteAccessTokenSql;
    }

    public void setSelectAccessTokenAuthenticationSql(String selectAccessTokenAuthenticationSql) {
        this.selectAccessTokenAuthenticationSql = selectAccessTokenAuthenticationSql;
    }

    public void setSelectAccessTokenFromAuthenticationSql(String selectAccessTokenFromAuthenticationSql) {
        this.selectAccessTokenFromAuthenticationSql = selectAccessTokenFromAuthenticationSql;
    }

    public void setSelectAccessTokensFromClientIdSql(String selectAccessTokensFromClientIdSql) {
        this.selectAccessTokensFromClientIdSql = selectAccessTokensFromClientIdSql;
    }

    private final class SafeAccessTokenRowMapper implements RowMapper<OAuth2AccessToken> {
        private SafeAccessTokenRowMapper() {
        }

        public OAuth2AccessToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            try {
                return MyJdbcTokenStore.this.deserializeAccessToken(rs.getBytes(2));
            } catch (IllegalArgumentException var5) {
                String token = rs.getString(1);
                MyJdbcTokenStore.this.jdbcTemplate.update(MyJdbcTokenStore.this.deleteAccessTokenSql, new Object[]{token});
                return null;
            }
        }
    }
}
