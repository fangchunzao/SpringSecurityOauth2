package oauth.security.client.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;


import java.util.*;

public class ApplyDetails implements ClientDetails{

    private final String clientId;

    private final String secret;

    private final Set<String> authorizedGrantTypes = new HashSet<String>(){{ add("client_credentials");  add("refresh_token");}};

    private final Set<String> scope = new HashSet<String>() {{add("all"); }};

    private  Collection<GrantedAuthority> authorities;


    public ApplyDetails(String clientId, String secret) {
        this.clientId = clientId;
        this.secret = secret;

        // this.authorities = authorities;

        System.out.println("adsad");
    }

    public String getSecret() {
        return secret;
    }

    @Override
    public String getClientId() {
        return this.clientId;
    }

    @Override
    public Set<String> getResourceIds() {
        return null;
    }

    @Override
    public boolean isSecretRequired() {
        return true;
    }

    @Override
    public String getClientSecret() {
        return this.secret;
    }

    @Override
    public boolean isScoped() {
        return true;
    }

    @Override
    public Set<String> getScope() {
        return this.scope;
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
        return this.authorizedGrantTypes;
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
        return null;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return null;
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return null;
    }

    @Override
    public boolean isAutoApprove(String s) {
        return false;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return null;
    }
}

