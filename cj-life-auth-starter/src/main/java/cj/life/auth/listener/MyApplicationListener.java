package cj.life.auth.listener;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class MyApplicationListener implements ApplicationListener {
    @Value("${spring.profiles.active}")
    private String springProfilesActive;
    @Value("${eureka.client.service-url.defaultZone}")
    private String EUREKA_SERVER_URL;
    @Value("${eureka.instance.hostname}")
    private String hostname;
    @Value("${life.security.auth_web.host}")
    private String security_auth_web_host;
    @Value("${spring.redis.database}")
    private String spring_redis_db;
    @Value("${spring.redis.hostName}")
    private String spring_redis_host;
    @Value("${spring.redis.port}")
    private String spring_redis_port;
    @Value("${spring.redis.password}")
    private String spring_redis_pwd;
    boolean runOnce;
    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (runOnce) {
            return;
        }
        System.out.println("Spring boot application.yml 生效的环境变量:");
        System.out.println("\tlife.spring.profiles.active="+springProfilesActive);
        System.out.println("\tlife.EUREKA_SERVER_URL="+EUREKA_SERVER_URL);
        System.out.println("\tlife.hostname="+hostname);
        System.out.println("\tlife.security_auth_web_host="+security_auth_web_host);
        System.out.println("\tlife.spring_redis_db="+spring_redis_db);
        System.out.println("\tlife.spring_redis_host="+spring_redis_host);
        System.out.println("\tlife.spring_redis_port="+spring_redis_port);
        System.out.println("\tlife.spring_redis_pwd="+spring_redis_pwd);
        runOnce=true;
    }
}
