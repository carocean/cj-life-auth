package cj.life.auth.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomerCorsFilter extends org.springframework.web.filter.CorsFilter {
    public CustomerCorsFilter() {
        super(configurationSource());
    }
 
    private static UrlBasedCorsConfigurationSource configurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
/*
        List<String> allowedHeaders = Arrays.asList("x-auth-token", "content-type", "X-Requested-With", "XMLHttpRequest","Access-Control-Allow-Origin","Authorization","authorization");
        List<String> exposedHeaders = Arrays.asList("x-auth-token", "content-type", "X-Requested-With", "XMLHttpRequest","Access-Control-Allow-Origin","Authorization","authorization");
        List<String> allowedMethods = Arrays.asList("POST", "GET", "DELETE", "PUT", "OPTIONS","PATCH");
        List<String> allowedOrigins = Arrays.asList("*");
        corsConfig.setAllowedHeaders(allowedHeaders);
        corsConfig.setAllowedMethods(allowedMethods);
//        corsConfig.setAllowedOrigins(allowedOrigins);
        corsConfig.setAllowedOriginPatterns(allowedOrigins);
        corsConfig.setExposedHeaders(exposedHeaders);

 */

        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(36000L);

        corsConfig.addAllowedHeader("*");
        corsConfig.addAllowedMethod("*");
//        corsConfig.addAllowedOrigin("*");
        corsConfig.addAllowedOriginPattern("*");
        corsConfig.addExposedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }
}

