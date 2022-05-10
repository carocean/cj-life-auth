package cj.life.auth.config;

import cj.life.auth.R;
import cj.life.auth.ResultCode;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;

/**
 * <pre>
 * 认证请求: GET http://localhost:8080/oauth/authorize?response_type=code&client_id=tao&redirect_uri=http://baidu.com&scope=all
 * 获取token: POST http://localhost:8080/oauth/token
 *
 * 认证请求: 校验用户账号密码，发放凭据，如授权码
 * 获取token： 根据凭据（如授权码）获取访问令牌（如access_token)
 * 访问资源: 首先根据凭据验证。即获取到用户身份（用户账号）；而后鉴权：根据角色或自定义来判断是否对资源拥有相应权限。
 * </pre>
 */
@Configuration
//@EnableWebFluxSecurity
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    ApplicationContext applicationContext;

    /**
     * websecurity用户密码和认证服务器客户端密码都需要加密算法
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {//密码加密
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .logout()
//                .logoutUrl(SecurityConstants.LOGOUT_URL)
//                .logoutSuccessHandler(logoutSuccessHandler)
//                .addLogoutHandler(logoutHandler)
                .clearAuthentication(true)
                .and()
                .requestMatchers()
                .antMatchers("/login", "/oauth/**", "/logout")
//                .antMatchers("/**")
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
//                .loginPage("http://localhost:8060/login.html")
//                .loginProcessingUrl("/login")
//                .failureHandler(myAuthenticationFailureHandler);
                .permitAll()
//                .disable()
                .and()
                .csrf().disable()
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这里配置全局用户信息
        UserDetailsService userDetailsService = (UserDetailsService) applicationContext.getBean("remoteUserDetailsService");
        auth.userDetailsService(userDetailsService);
        AuthenticationProvider authenticationProvider = (AuthenticationProvider) applicationContext.getBean("ucAuthenticationProvider");
        auth.authenticationProvider(authenticationProvider);
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return ((request, response, e) -> {
            response.setStatus(HttpStatus.OK.value());
            response.setHeader("Content-Type", "application/json;charset=utf-8");
            Object obj = R.of(ResultCode.ACCESS_DENIED, e.getMessage());
            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
        });
    }

    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return ((request, response, e) -> {
            response.setStatus(HttpStatus.OK.value());
            response.setHeader("Content-Type", "application/json;charset=utf-8");
            ResultCode rc = null;
            if (e instanceof BadCredentialsException) {
                rc = ResultCode.BAD_CREDENTIALS;
            } else if (e instanceof InsufficientAuthenticationException) {
                rc = ResultCode.INSUFFICIENT_AUTHENTICATION;
            } else if (e instanceof SessionAuthenticationException) {
                rc = ResultCode.SESSION_AUTHENTICATION;
            } else if (e instanceof UsernameNotFoundException) {
                rc = ResultCode.USERNAME_NOT_FOUND;
            } else if (e instanceof PreAuthenticatedCredentialsNotFoundException) {
                rc = ResultCode.PRE_AUTHENTICATED_CREDENTIALS;
            } else if (e instanceof AuthenticationServiceException) {
                rc = ResultCode.AUTHENTICATION_SERVICE;
            } else if (e instanceof ProviderNotFoundException) {
                rc = ResultCode.PROVIDER_NOTFOUND;
            } else if (e instanceof AuthenticationCredentialsNotFoundException) {
                rc = ResultCode.AUTHENTICATION_CREDENTIALS;
            } else if (e instanceof RememberMeAuthenticationException) {
                rc = ResultCode.REMEMBER_ME_AUTHENTICATION;
            } else if (e instanceof NonceExpiredException) {
                rc = ResultCode.NONCE_EXPIRED;
            } else if (e instanceof AccountStatusException) {
                rc = ResultCode.ACCOUNT_STATUS;
            } else {
                rc = ResultCode.ERROR_UNKNOWN;
            }
            Object obj = R.of(rc, e.getMessage());
            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
        });
    }

    @Bean
    public WebResponseExceptionTranslator customExceptionTranslator() {
        return (e -> {
            OAuth2Exception exception = (OAuth2Exception) e;
            String errorCode = exception.getOAuth2ErrorCode();
            ResultCode rc = null;
            if ("invalid_client".equals(errorCode)) {
                rc = ResultCode.INVALID_CLIENT;
            } else if ("unauthorized_client".equals(errorCode)) {
                rc = ResultCode.UNAUTHORIZED_CLIENT;
            } else if ("invalid_grant".equals(errorCode)) {
                rc = ResultCode.INVALID_GRANT;
            } else if ("invalid_scope".equals(errorCode)) {
                rc = ResultCode.INVALID_SCOPE;
            } else if ("invalid_token".equals(errorCode)) {
                rc = ResultCode.INVALID_TOKEN;
            } else if ("invalid_request".equals(errorCode)) {
                rc = ResultCode.INVALID_REQUEST;
            } else if ("redirect_uri_mismatch".equals(errorCode)) {
                rc = ResultCode.REDIRECT_URI_MISMATCH;
            } else if ("unsupported_grant_type".equals(errorCode)) {
                rc = ResultCode.UNSUPPORTED_GRANT_TYPE;
            } else if ("unsupported_response_type".equals(errorCode)) {
                rc = ResultCode.UNSUPPORTED_RESPONSE_TYPE;
            } else {
                rc = ("access_denied".equals(errorCode) ? ResultCode.ACCESS_DENIED : ResultCode.OAUTH2_ERROR);
            }
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .header("Content-Type", "application/json;charset=utf-8")
                    .body(R.of(rc, e.getMessage()));
        });
    }
}

