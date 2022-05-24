package cj.life.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication(scanBasePackages = { "cj.life.auth"})
@EnableEurekaClient
@EnableFeignClients(basePackages = "cj.life.auth")
public class CjLifeAuthStarterApplication {

    public static void main(String[] args) {
        SpringApplication.run(CjLifeAuthStarterApplication.class, args);
    }
}
