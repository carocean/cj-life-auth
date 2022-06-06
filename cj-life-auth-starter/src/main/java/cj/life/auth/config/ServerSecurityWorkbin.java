package cj.life.auth.config;

import cj.life.ability.oauth2.annotation.EnableOAuth2Server;
import cj.life.ability.oauth2.config.SecurityWorkbin;
import cj.life.ability.redis.annotation.EnableRedis;
import cj.life.auth.workbin.ExampleClientDetailsService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.ClientDetailsService;

@EnableRedis
@EnableOAuth2Server
@Configuration
public class ServerSecurityWorkbin extends SecurityWorkbin {
    @Override
    public ClientDetailsService clientDetailsService() {
        return new ExampleClientDetailsService();
    }
}
