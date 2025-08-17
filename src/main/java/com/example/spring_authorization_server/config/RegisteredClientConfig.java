package com.example.spring_authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Tạo một client đơn giản
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client")                    // ID của client
                .clientSecret("{noop}my-secret")          // Secret (noop = không mã hóa)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // Luồng Authorization Code
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)       // Cho phép refresh token
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // Luồng Client Credentials (đơn giản nhất)
                .redirectUri("http://localhost:8080/callback")  // URL callback sau khi authorize
                .scope("read")      // Scope đọc
                .scope("write")     // Scope ghi
                .build();

        // Lưu client trong memory
        return new InMemoryRegisteredClientRepository(client);
    }
}