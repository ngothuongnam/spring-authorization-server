package com.example.spring_authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Tạo một client đơn giản với cấu hình tối ưu cho CORS
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client")                    // ID của client
                .clientSecret("{noop}my-secret")          // Secret (noop = không mã hóa)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // Luồng Authorization Code
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)       // Cho phép refresh token
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // ✅ Luồng Client Credentials (cho frontend)
                .redirectUri("http://localhost:8080/callback")  // URL callback sau khi authorize
                .redirectUri("http://127.0.0.1:5500/callback") // ✅ Cho Live Server
                .redirectUri("http://localhost:3000/callback") // ✅ Cho React dev server
                .scope("read")      // Scope đọc
                .scope("write")     // Scope ghi
                // ✅ Token settings - quan trọng cho client_credentials
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(60)) // Token expires in 60 minutes
                        .refreshTokenTimeToLive(Duration.ofHours(8))    // Refresh token expires in 8 hours
                        .build())
                // ✅ Client settings
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) // ✅ Không cần consent cho client_credentials
                        .build())
                .build();

        // Lưu client trong memory
        return new InMemoryRegisteredClientRepository(client);
    }
}