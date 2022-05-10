package cj.life.auth.config;

import cj.life.auth.exception.CustomClientCredentialsTokenEndpointFilter;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Configuration
@EnableAuthorizationServer
//@EnableOAuth2Sso
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    AuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    WebResponseExceptionTranslator customExceptionTranslator;
    @Autowired
    ClientDetailsService remoteClientDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        CustomClientCredentialsTokenEndpointFilter endpointFilter = new CustomClientCredentialsTokenEndpointFilter(security);
        endpointFilter.afterPropertiesSet();
        endpointFilter.setAuthenticationEntryPoint(customAuthenticationEntryPoint);
//        如果没有下面的配置是可以正常获取code的，但是在请求access_token的时候会出现401的错误
        security
                //允许表单验证，对应还有basic认证，basic认证是客户端调用系统本地的验证窗口，如果充许则走ClientCredentialsTokenEndpointFilter，自定义的filter和认证入口点不被执行
//                .allowFormAuthenticationForClients()
                // 开启/oauth/token_key验证端口无权限访问
                .tokenKeyAccess("permitAll()")
                // 开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()")
                .addTokenEndpointAuthenticationFilter(endpointFilter)
        ;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(remoteClientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenEnhancer(createTokenEnhancer())
                .exceptionTranslator(customExceptionTranslator)
                .userDetailsService(userDetailsService)
                /*
                    https://www.cnblogs.com/xingxueliao/p/5911292.html
                    https://www.wetsion.site/spring-security-oauth2-authrize-confirm.html
                    以上的参数都将以 "/" 字符为开始的字符串，框架的默认URL链接如下列表，可以作为这个 pathMapping() 方法的第一个参数：
                    /oauth/authorize：授权端点。
                    /oauth/token：令牌端点。
                    /oauth/confirm_access：用户确认授权提交端点。
                    /oauth/error：授权服务错误信息端点。
                    /oauth/check_token：用于资源服务访问的令牌解析端点。
                    /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话。
                 */
//                .pathMapping("/oauth/confirm_access", "http://localhost:8100/confirm_access.html")
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
        ;//使用WebSecurityConfig中的userDetailsService，如果为空则在WebSecurityConfig开放为bean
    }


    private TokenEnhancer createTokenEnhancer() {
        return (accessToken, authentication) -> {
            if (accessToken instanceof DefaultOAuth2AccessToken) {
                DefaultOAuth2AccessToken token = ((DefaultOAuth2AccessToken) accessToken);
                token.setValue(createNewToken());
                token.setRefreshToken(new DefaultOAuth2RefreshToken(createNewToken()));
                token.setAdditionalInformation(accessToken.getAdditionalInformation());
                return token;
            }
            return accessToken;
        };
    }

    private String createNewToken() {
        return DigestUtils.md5Hex(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

}

