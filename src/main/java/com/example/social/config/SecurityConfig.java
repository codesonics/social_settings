package com.example.social.config;

import java.util.Arrays;
import java.util.List;

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
    private final FacebookOauth2UserService facebookOauth2UserService;
    private static final String DEFAULT_LOGIN_REDIRECT_URL = "http://localhost:8080/login/oauth2/code/kakao";
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests( authorize ->
                        authorize.antMatchers("login", "/index").permitAll()
                                .anyRequest().authenticated()

                )
                //.oauth2Login(Customizer.withDefaults())
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(oAuth2AuthorizedClientService())
                        .userInfoEndpoint(user ->
                                user
                                        /*.oidcUserService()*/
                                        .userService(facebookOauth2UserService)

                        )
                )
                ;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties){
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration(),
                kakaoClientRegistration(properties)
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
    private ClientRegistration kakaoClientRegistration(OAuth2ClientProperties properties) {
        OAuth2ClientProperties.Registration registration
                = properties.getRegistration().get(KAKAO.getValue());
        OAuth2ClientProperties.Provider provider = properties.getProvider().get(KAKAO.getValue());
        return ClientRegistration.withRegistrationId(KAKAO.getValue())
                .clientId(registration.getClientId())
                .clientSecret(registration.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(DEFAULT_LOGIN_REDIRECT_URL)
                .scope(registration.getScope())
                .authorizationUri(provider.getAuthorizationUri())
                .tokenUri(provider.getTokenUri())
                .userInfoUri(provider.getUserInfoUri())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName("Kakao")
                .build();
    }
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
