package com.example.social.config;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ch.qos.logback.core.net.server.Client;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import static com.example.social.user.SocialType.KAKAO;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final Environment environment;
    private final String registration = "spring.security.oauth2.client.registration.";
    private final CustomOAuth2UserService customOAuth2UserService;
    private static final String DEFAULT_LOGIN_REDIRECT_URL = "{baseUrl}/login/oauth2/code/";
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests( authorize ->
                        authorize.antMatchers("login", "/index").permitAll()
                                .anyRequest().authenticated()

                )
                .oauth2Login().userInfoEndpoint().userService(customOAuth2UserService)

                //.oauth2Login(Customizer.withDefaults())
               /* .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(oAuth2AuthorizedClientService())
                        .userInfoEndpoint(user ->
                                user
                                        //.oidcUserService()
                                        .userService(customOAuth2UserService)

                        )
                        //.defaultSuccessUrl()
                        //.failureHandler()
                )*/

                ;

/*        http
                    .headers().frameOptions().disable()
                .and()
                    .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/member/update").authenticated()
                        .anyRequest().permitAll()
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                .and()
                    .formLogin()
                    .loginPage("/login" )
                    .permitAll()
                    .usernameParameter("j_username")
                    .passwordParameter("j_password")
                    .loginProcessingUrl("/j_spring_security_check")
                    .defaultSuccessUrl("/", false)
                    .failureUrl("/login" + "?login=fail")
                .and()
                    .oauth2Login()
                    .userInfoEndpoint()
                    .userService(customOAuth2UserService)
                .and()
                    .defaultSuccessUrl("/",false)
                .and()
                    .logout().permitAll()
                    .logoutUrl("/j_spring_security_logout")
                    .logoutSuccessUrl("/")
                    .deleteCookies("JSESSIONID")
                    .invalidateHttpSession(true)
                .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                    .sessionFixation().migrateSession()
                    .maximumSessions(3)
        ;*/
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties){

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull) .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    public ClientRegistration getRegistration(OAuth2ClientProperties oAuth2ClientProperties, String client) {

        OAuth2ClientProperties.Registration registration = oAuth2ClientProperties.getRegistration().get(client);
        String clientId = registration.getClientId();
        String clientSecret = registration.getClientSecret();

        if (clientId == null) {
            return null;
        }

        switch (client){//구글, 페이스북은 제공, 네이버 카카오는 따로 Provider 선언해줘야함
            case "google":
                return CustomOAuth2Provider.GOOGLE.getBuilder(client)
                        .clientId(clientId).clientSecret(clientSecret).build();
            case "facebook":
                return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                        .clientId(clientId).clientSecret(clientSecret).build();
            case "kakao":
                return CustomOAuth2Provider.KAKAO.getBuilder(client)
                        .clientId(clientId)
                        .clientSecret(clientSecret).build();
            case "naver":
                return CustomOAuth2Provider.NAVER.getBuilder(client)
                        .clientId(clientId)
                        .clientSecret(clientSecret).build();
        }
        return null;
    }

/*

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration(),
                kakaoClientRegistration()
        );
        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }
    @Bean
    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService(){
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }
    private ClientRegistration googleClientRegistration(){
        final String clientId = environment.getProperty(registration + "google.client-id");
        final String clientSecret = environment.getProperty(registration + "google.client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }
    private ClientRegistration facebookClientRegistration() {
        final String clientId = environment.getProperty(registration + "facebook.client-id");
        final String clientSecret = environment.getProperty(registration + "facebook.client-secret");

        return CommonOAuth2Provider
                .FACEBOOK
                .getBuilder("facebook")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .scope(
                        "public_profile",
                        "email",
                        "user_birthday",
                        "user_gender"
                )
                .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,picture,gender,birthday")
                .build();
    }
    private ClientRegistration kakaoClientRegistration() {
        final String clientId = environment.getProperty(registration + KAKAO.getValue() + ".client-id");
        final String clientSecret = environment.getProperty(registration + KAKAO.getValue() + ".client-secret");
        return ClientRegistration.withRegistrationId(KAKAO.getValue())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(DEFAULT_LOGIN_REDIRECT_URL + KAKAO.getValue())
                .scope("account_email", "profile")
                .authorizationUri("https://kauth.kakao.com/oauth/authorize")
                .tokenUri("https://kauth.kakao.com/oauth/token")
                .userInfoUri("https://kapi.kakao.com/v2/user/me")
                .userNameAttributeName("id")
                .clientName("Kakao")
                .build();
    }*/
    /*private final Environment environment;
    private final String registration = "spring.security.oauth2.client.registration.";

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
            .authorizeRequests(authorize -> authorize
                .antMatchers("/login", "/index").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
            )
        ;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
            googleClientRegistration(),
            facebookClientRegistration()
        );

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    private ClientRegistration googleClientRegistration() {
        final String clientId = environment.getProperty(registration + "google.client-id");
        final String clientSecret = environment.getProperty(registration + "google.client-secret");

        return CommonOAuth2Provider
            .GOOGLE
            .getBuilder("google")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build();
    }

    private ClientRegistration facebookClientRegistration() {
        final String clientId = environment.getProperty(registration + "facebook.client-id");
        final String clientSecret = environment.getProperty(registration + "facebook.client-secret");

        return CommonOAuth2Provider
            .FACEBOOK
            .getBuilder("facebook")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .scope(
                "public_profile",
                "email",
                "user_birthday",
                "user_gender"
            )
            .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,picture,gender,birthday")
            .build();
    }*/
}
