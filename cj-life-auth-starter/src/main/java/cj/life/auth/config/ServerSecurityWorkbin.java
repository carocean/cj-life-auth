package cj.life.auth.config;

import cj.life.ability.oauth2.annotation.EnableOAuth2Server;
import cj.life.ability.oauth2.config.SecurityWorkbin;
import cj.life.ability.redis.annotation.EnableRedis;
import org.springframework.context.annotation.Configuration;
@EnableRedis
@EnableOAuth2Server
@Configuration
public class ServerSecurityWorkbin extends SecurityWorkbin {

}
