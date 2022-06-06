package cj.life.auth.workbin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ExampleClientDetailsService implements ClientDetailsService {
    @Autowired
    PasswordEncoder passwordEncoder;

    public ExampleClientDetailsService() {
    }

    public ClientDetails loadClientByClientId(String client_id) throws ClientRegistrationException {
        if (!"client1".equals(client_id)) {
            throw new NoSuchClientException("不存在");
        } else {
            BaseClientDetails clientDetails = new BaseClientDetails();
            clientDetails.setClientId(client_id);
            clientDetails.setClientSecret(this.passwordEncoder.encode("client1_secret"));
            clientDetails.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token", "implicit", "sms_code", "tenant_code"));
            clientDetails.setScope(Arrays.asList("all", "ROLE_ADMIN", "ROLE_USER"));
            clientDetails.setAutoApproveScopes(Arrays.asList("false"));
            Set<String> set = new HashSet();
            set.add("http://localhost:8060/welcome");
            clientDetails.setRegisteredRedirectUri(set);
            clientDetails.setAccessTokenValiditySeconds(7200);
            return clientDetails;
        }
    }
}