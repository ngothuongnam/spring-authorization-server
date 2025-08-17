# 📚 Hướng dẫn Spring Authorization Server - Tài liệu học tập

## 📋 Mục lục
1. [Giới thiệu và khái niệm cơ bản](#1-giới-thiệu-và-khái-niệm-cơ-bản)
2. [Cấu trúc project và dependencies](#2-cấu-trúc-project-và-dependencies)
3. [Chi tiết từng file cấu hình](#3-chi-tiết-từng-file-cấu-hình)
4. [Luồng hoạt động và các endpoint](#4-luồng-hoạt-động-và-các-endpoint)
5. [Test với Postman](#5-test-với-postman)
6. [Troubleshooting và lỗi thường gặp](#6-troubleshooting-và-lỗi-thường-gặp)
7. [Nâng cao cho Production](#7-nâng-cao-cho-production)

---

## 1. Giới thiệu và khái niệm cơ bản

### 1.1. OAuth 2.0 là gì?
**OAuth 2.0** là một **chuẩn ủy quyền** cho phép ứng dụng truy cập tài nguyên của user mà không cần biết password.

### 1.2. Các thành phần chính:
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client App    │───▶│Authorization     │───▶│  Resource       │
│                 │    │Server            │    │  Server (API)   │
│ (Web/Mobile App)│    │ (Cấp token)      │    │ (Dữ liệu)       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        ▲                        │                        ▲
        │                        ▼                        │
        │               ┌──────────────────┐              │
        └───────────────│      User        │──────────────┘
                        │   (Đăng nhập)    │
                        └──────────────────┘
```

### 1.3. Các Grant Types (Cách lấy token):

#### **Client Credentials Flow** (Server-to-Server):
```
Client ────POST /oauth2/token───▶ Auth Server
       ◀───── Access Token ──────┘
```
- Không cần user tương tác
- Dành cho backend services

#### **Authorization Code Flow** (Web Applications):
```
1. User ─────GET /oauth2/authorize───▶ Auth Server
2. Auth Server ────Login Form────────▶ User  
3. User ──────Login Credentials──────▶ Auth Server
4. Auth Server ─────Redirect + Code──▶ Client
5. Client ────POST /oauth2/token─────▶ Auth Server
6. Auth Server ────Access Token──────▶ Client
```

### 1.4. JWT Token Structure:
```
Header.Payload.Signature

// Example:
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInNjb3BlIjoicmVhZCJ9.signature
```

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "admin",
  "scope": ["read", "write"],
  "iss": "http://localhost:9000",
  "exp": 1672531200
}
```

---

## 2. Cấu trúc project và dependencies

### 2.1. File pom.xml:
```xml
<dependencies>
    <!-- Spring Authorization Server -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
    </dependency>
    
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- Spring Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

### 2.2. Cấu trúc thư mục:
```
src/main/java/com/example/spring_authorization_server/
├── config/
│   ├── AuthorizationServerConfig.java    # Cấu hình OAuth2 endpoints
│   ├── RegisteredClientConfig.java       # Cấu hình clients
│   └── SecurityConfig.java               # Cấu hình users & security
├── SpringAuthorizationServerApplication.java
└── resources/
    └── application.properties            # Cấu hình server
```

### 2.3. File application.properties:
```properties
# Server port
server.port=9000

# Logging để debug
logging.level.org.springframework.security=DEBUG
```

---

## 3. Chi tiết từng file cấu hình

### 3.1. AuthorizationServerConfig.java

```java
@Configuration
public class AuthorizationServerConfig {

    // Filter Chain 1: OAuth2 Endpoints
    @Bean
    @Order(1)
    public SecurityFilterChain authServerFilterChain(HttpSecurity http) throws Exception {
        http
            // CHỈ áp dụng cho OAuth2 URLs
            .securityMatcher("/oauth2/**", "/.well-known/**")
            
            // Kích hoạt OAuth2 Authorization Server
            .with(new OAuth2AuthorizationServerConfigurer(), Customizer.withDefaults())
            
            // Tất cả requests cần authentication
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            
            // Redirect về /login nếu chưa đăng nhập (browser)
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );
        
        return http.build();
    }

    // Filter Chain 2: Web UI
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            // Áp dụng cho TẤT CẢ URLs còn lại
            .securityMatcher("/**")
            
            .authorizeHttpRequests(auth -> auth
                // Cho phép truy cập login/error không cần xác thực
                .requestMatchers("/login", "/error").permitAll()
                .anyRequest().authenticated()
            )
            
            // Form login mặc định
            .formLogin(Customizer.withDefaults());
        
        return http.build();
    }
}
```

**🔍 Giải thích chi tiết:**

**@Order(1) và @Order(2):**
- Spring Security xử lý theo thứ tự ưu tiên
- Order càng nhỏ, ưu tiên càng cao

**securityMatcher():**
- Xác định filter chain này áp dụng cho URLs nào
- Tránh conflict giữa các filter chains

**OAuth2AuthorizationServerConfigurer:**
- Tự động tạo các endpoints: `/oauth2/token`, `/oauth2/authorize`, v.v.
- Cấu hình JWT signing, validation

**defaultAuthenticationEntryPointFor:**
- Browser requests (HTML) → redirect về `/login`
- API requests (JSON) → trả về 401 status

### 3.2. RegisteredClientConfig.java

```java
@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        
        // Tạo một client (ứng dụng) đã đăng ký
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                
                // Thông tin client
                .clientId("my-client")                    // Username của client
                .clientSecret("{noop}my-secret")          // Password của client
                
                // Cách client xác thực với Auth Server
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                
                // Các cách client có thể lấy token
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // Web apps
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)       // Refresh token
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // Server-to-server
                
                // URL callback sau khi user authorize
                .redirectUri("http://localhost:8080/callback")
                
                // Quyền hạn mà token có thể có
                .scope("read")      // Đọc dữ liệu
                .scope("write")     // Ghi dữ liệu
                .build();

        // Lưu client info trong memory (RAM)
        return new InMemoryRegisteredClientRepository(client);
    }
}
```

**🔍 Giải thích chi tiết:**

**clientId/clientSecret:**
- Giống như username/password cho ứng dụng
- Client phải gửi credentials này để lấy token

**{noop}:**
- No Operation - không mã hóa password
- Chỉ dùng để test, production phải mã hóa

**CLIENT_SECRET_BASIC:**
- Client gửi credentials qua HTTP Basic Auth header
- `Authorization: Basic base64(clientId:clientSecret)`

**Grant Types:**
- **AUTHORIZATION_CODE**: Dành cho web apps có backend
- **CLIENT_CREDENTIALS**: Dành cho server-to-server communication
- **REFRESH_TOKEN**: Cho phép refresh access token khi hết hạn

**redirectUri:**
- Sau khi user đăng nhập, browser sẽ redirect về URL này
- URL này phải được đăng ký trước, không thể thay đổi tùy ý

**Scopes:**
- Định nghĩa quyền hạn của token
- Resource Server sẽ kiểm tra scope để quyết định cho phép hay từ chối

### 3.3. SecurityConfig.java

```java
@Configuration
public class SecurityConfig {

    // Tạo user để đăng nhập test
    @Bean
    public UserDetailsService userDetailsService() {
        
        // Tạo user trong memory
        var user = User.withUsername("admin")
                .password("{noop}password")  // Plain text password
                .authorities("ROLE_USER")    // Vai trò của user
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    // Password encoder (bắt buộc với Spring Security)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

**🔍 Giải thích chi tiết:**

**UserDetailsService:**
- Interface để load thông tin user từ database/memory/file
- Spring Security sẽ gọi service này khi user đăng nhập

**InMemoryUserDetailsManager:**
- Lưu user info trong RAM
- Mất dữ liệu khi restart server
- Chỉ dùng để test

**DelegatingPasswordEncoder:**
- Hỗ trợ nhiều format password: `{noop}`, `{bcrypt}`, `{sha256}`
- Tự động detect format và decode accordingly

---

## 4. Luồng hoạt động và các endpoint

### 4.1. Endpoints được tạo tự động:

| Endpoint | Method | Mục đích |
|----------|--------|----------|
| `/.well-known/oauth-authorization-server` | GET | Metadata của server |
| `/oauth2/authorize` | GET | Trang authorize cho users |
| `/oauth2/token` | POST | Lấy access token |
| `/oauth2/jwks` | GET | Public keys để verify JWT |
| `/oauth2/revoke` | POST | Thu hồi token |
| `/oauth2/introspect` | POST | Kiểm tra token status |

### 4.2. Client Credentials Flow:

```
Step 1: Client Request Token
POST /oauth2/token
Authorization: Basic bXktY2xpZW50Om15LXNlY3JldA==
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read

Step 2: Server Response
{
    "access_token": "eyJhbGciOiJSUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 300,
    "scope": "read"
}

Step 3: Client Use Token
GET /api/data
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

### 4.3. Authorization Code Flow:

```
Step 1: Redirect User to Auth Server
GET /oauth2/authorize?response_type=code&client_id=my-client&redirect_uri=http://localhost:8080/callback&scope=read

Step 2: User Login
POST /login
username=admin&password=password

Step 3: Redirect with Code
HTTP 302 Redirect
Location: http://localhost:8080/callback?code=ABC123

Step 4: Exchange Code for Token
POST /oauth2/token
Authorization: Basic bXktY2xpZW50Om15LXNlY3JldA==
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ABC123&redirect_uri=http://localhost:8080/callback

Step 5: Server Response Token
{
    "access_token": "eyJhbGciOiJSUzI1NiJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 300,
    "scope": "read"
}
```

---

## 5. Test với Postman

### 5.1. Khởi động server:
```bash
mvn clean package -DskipTests
mvn spring-boot:run
```

### 5.2. Test Client Credentials (Đơn giản nhất):

**Request:**
- **Method:** POST
- **URL:** `http://localhost:9000/oauth2/token`
- **Authorization Tab:**
  - Type: Basic Auth
  - Username: `my-client`
  - Password: `my-secret`
- **Body Tab:**
  - Type: x-www-form-urlencoded
  - Keys:
    - `grant_type`: `client_credentials`
    - `scope`: `read`

**Response:**
```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "scope": "read",
    "token_type": "Bearer",
    "expires_in": 300
}
```

### 5.3. Test Well-known Configuration:

**Request:**
- **Method:** GET
- **URL:** `http://localhost:9000/.well-known/oauth-authorization-server`

**Response:**
```json
{
    "issuer": "http://localhost:9000",
    "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
    "token_endpoint": "http://localhost:9000/oauth2/token",
    "jwks_uri": "http://localhost:9000/oauth2/jwks",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

### 5.4. Test Authorization Code Flow:

**Step 1:** Mở browser
```
http://localhost:9000/oauth2/authorize?response_type=code&client_id=my-client&redirect_uri=http://localhost:8080/callback&scope=read
```

**Step 2:** Đăng nhập (`admin` / `password`)

**Step 3:** Copy authorization code từ URL callback

**Step 4:** Postman request
- **Method:** POST
- **URL:** `http://localhost:9000/oauth2/token`
- **Authorization:** Basic Auth (`my-client` / `my-secret`)
- **Body:**
  - `grant_type`: `authorization_code`
  - `code`: `[CODE_FROM_STEP_3]`
  - `redirect_uri`: `http://localhost:8080/callback`

---

## 6. Troubleshooting và lỗi thường gặp

### 6.1. Lỗi Filter Chain Conflict:
```
Error: Multiple filter chains configured for 'any request'
```

**Nguyên nhân:** Nhiều SecurityFilterChain cùng handle "/**"

**Giải pháp:** Sử dụng `securityMatcher()` để phân chia rõ ràng:
```java
@Bean
@Order(1)
public SecurityFilterChain authServerFilterChain(HttpSecurity http) {
    http.securityMatcher("/oauth2/**", "/.well-known/**")
        // ...
}

@Bean  
@Order(2)
public SecurityFilterChain webFilterChain(HttpSecurity http) {
    http.securityMatcher("/**")
        // ...
}
```

### 6.2. Lỗi 401 Unauthorized:
```json
{
    "error": "unauthorized",
    "error_description": "Full authentication is required"
}
```

**Nguyên nhân:** 
- Sai client credentials
- Chưa cấu hình Basic Auth trong Postman

**Giải pháp:**
- Kiểm tra `clientId`: `my-client`
- Kiểm tra `clientSecret`: `my-secret`
- Đảm bảo chọn Basic Auth trong Postman

### 6.3. Lỗi 400 Bad Request:
```json
{
    "error": "invalid_grant",
    "error_description": "Invalid authorization code"
}
```

**Nguyên nhân:** Authorization code đã được sử dụng hoặc hết hạn

**Giải pháp:** Lấy authorization code mới từ browser

### 6.4. Lỗi Deprecated Methods:
```
'applyDefaultSecurity' is deprecated since version 1.4
```

**Giải pháp:** Sử dụng cách mới:
```java
// Cũ (deprecated)
OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

// Mới
http.with(new OAuth2AuthorizationServerConfigurer(), Customizer.withDefaults())
```

### 6.5. Lỗi Port Already in Use:
```
Port 9000 was already in use
```

**Giải pháp:**
- Thay đổi port trong `application.properties`: `server.port=9001`
- Hoặc kill process: `lsof -ti:9000 | xargs kill -9`

### 6.6. Lỗi Maven Test Failed:
```
Failed to execute goal maven-surefire-plugin:test
```

**Giải pháp:** Skip tests khi build:
```bash
mvn clean package -DskipTests
```

---

## 7. Nâng cao cho Production

### 7.1. Sử dụng Database thay vì Memory:

**UserDetailsService với JPA:**
```java
@Entity
public class User {
    @Id
    private String username;
    private String password;
    private String roles;
    // getters/setters
}

@Bean
public UserDetailsService userDetailsService(UserRepository userRepo) {
    return username -> {
        User user = userRepo.findByUsername(username);
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getRoles().split(","))
                .build();
    };
}
```

**RegisteredClientRepository với Database:**
```java
@Bean
public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    return new JdbcRegisteredClientRepository(jdbcTemplate);
}
```

### 7.2. Sử dụng BCrypt Password:

```java
// Trong SecurityConfig
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// Tạo user với BCrypt password
var user = User.withUsername("admin")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDDiQDnB8S3E7xSdQt8TbqOjutPQU6Ny")
        .authorities("ROLE_USER")
        .build();
```

### 7.3. HTTPS Configuration:

**application.properties:**
```properties
server.port=9443
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=password
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=tomcat
```

**Tạo keystore:**
```bash
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650
```

### 7.4. Custom JWT Claims:

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return (context) -> {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims((claims) -> {
                claims.put("custom_claim", "custom_value");
                claims.put("user_role", "admin");
            });
        }
    };
}
```

### 7.5. External RSA Keys:

```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
    // Load từ file thay vì generate random
    try {
        Resource resource = new ClassPathResource("jwt-key.pem");
        String privateKeyContent = Files.readString(resource.getFile().toPath());
        
        // Parse private key
        RSAPrivateKey privateKey = parseRSAPrivateKey(privateKeyContent);
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), RSAKeyGenParameterSpec.F4));
        
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("jwt-key-id")
                .build();
                
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    } catch (Exception e) {
        throw new RuntimeException("Failed to load JWT keys", e);
    }
}
```

### 7.6. Token Settings:

```java
@Bean
public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("production-client")
            .clientSecret("{bcrypt}$2a$10$...")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://myapp.com/callback")
            .scope(OidcScopes.OPENID)
            .scope("read")
            .scope("write")
            .clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(true)  // Hiện consent screen
                    .requireProofKey(true)              // PKCE required
                    .build())
            .tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))      // Access token: 5 phút
                    .refreshTokenTimeToLive(Duration.ofHours(8))       // Refresh token: 8 giờ
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2)) // Auth code: 2 phút
                    .reuseRefreshTokens(false)                         // Không reuse refresh token
                    .build())
            .build();

    return new InMemoryRegisteredClientRepository(client);
}
```

### 7.7. Logging và Monitoring:

**application.properties:**
```properties
# Logging
logging.level.org.springframework.security=INFO
logging.level.org.springframework.security.oauth2=DEBUG
logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} - %msg%n

# Actuator endpoints
management.endpoints.web.exposure.include=health,info,metrics
management.endpoint.health.show-details=always
```

**Dependencies:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

---

## 🎯 Tóm tắt các bước quan trọng

### Bước 1: Setup Project
1. Tạo Spring Boot project với dependencies OAuth2 Authorization Server
2. Cấu hình `application.properties`

### Bước 2: Cấu hình Security
1. `AuthorizationServerConfig` - OAuth2 endpoints
2. `RegisteredClientConfig` - Client applications  
3. `SecurityConfig` - Users và authentication

### Bước 3: Test
1. Client Credentials flow (đơn giản)
2. Authorization Code flow (phức tạp)
3. Kiểm tra các endpoints metadata

### Bước 4: Production Ready
1. Database integration
2. HTTPS configuration
3. External key management
4. Monitoring và logging

---

## 📞 Kết luận

Tài liệu này cung cấp kiến thức từ cơ bản đến nâng cao về Spring Authorization Server. 

**Để học hiệu quả:**
1. Đọc và hiểu lý thuyết OAuth 2.0
2. Thực hành code từng bước
3. Test với Postman để hiểu luồng hoạt động
4. Dần dần áp dụng các tính năng nâng cao

**Resources để học thêm:**
- [Spring Authorization Server Documentation](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [JWT.io](https://jwt.io) - JWT decoder/encoder

Chúc bạn học tập thành công! 🚀