package com.dodaso.ecosystem.user.auth.sso.config;

import com.dodaso.ecosystem.user.auth.sso.handler.OAuth2AuthenticationSuccessHandler;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AuthServerConfig {

  private final OAuth2AuthenticationSuccessHandler authenticationSuccessHandler;

  // Allow-listed landing pages for post-logout redirect. Exact match only --
  // do NOT switch this to prefix/contains matching or URI-parsing-based
  // validation, both of which are common open-redirect footguns. Add an
  // entry here for every app that's allowed to redirect back to itself
  // after logout.
  private static final Set<String> ALLOWED_POST_LOGOUT_REDIRECTS = Set.of(
      "https://localhost/elcm/",
      "https://localhost/ecws/",
      "https://localhost:443/elcm/",
      "https://localhost:443/ecws/"
  );
  private static final String DEFAULT_POST_LOGOUT_REDIRECT = "https://localhost:443/";

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerFilterChain(HttpSecurity httpSecurity)
      throws Exception {
    // Use the newer approach instead of applyDefaultSecurity()
    httpSecurity
        .securityMatcher("/oauth2/**", "/.well-known/openid-configuration", "/userinfo")
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/login",
            "/.well-known/openid_configuration", "/jwks", "/userinfo"))
        .with(new OAuth2AuthorizationServerConfigurer(), authzServer ->
            authzServer.oidc(Customizer.withDefaults())
        )
        .oauth2ResourceServer(resourceServer -> resourceServer
            .jwt(Customizer.withDefaults())
        );

    // Explicitly force redirect to /login when unauthorized or session expired
    httpSecurity.exceptionHandling(exceptions -> exceptions
        .defaultAuthenticationEntryPointFor(
            new LoginUrlAuthenticationEntryPoint("/login"),
            //new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            new MediaTypeRequestMatcher(MediaType.ALL)
        )
    );

    return httpSecurity.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain appFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(registry -> registry
            .requestMatchers("/login").permitAll()
            .requestMatchers("/*.css").permitAll()       // Root-level CSS
            .requestMatchers("/*.ico").permitAll()       // Root-level ICO
            .requestMatchers("/js/**").permitAll()       // All files under /js/
            .requestMatchers("/error").permitAll()       // Error path
            .requestMatchers("/css/**").permitAll()      // All CSS files under /css/
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/login")
            //.successHandler(authenticationSuccessHandler) // Custom success handler
            //.failureHandler(createAuthenticationFailureHandler())
            // New: sends users to the app-icon launcher panel after login,
            // but ONLY when there's no bookmarked deep link to replay --
            // "false" here is what makes that conditional (Spring Security's
            // saved-request replay still wins when one exists). See
            // AppLauncherController for the /apps endpoint itself.
            .defaultSuccessUrl("/apps", false)
            .permitAll()
        ).logout(l -> l
            .logoutUrl("/logout")
            // Fix #4: was a single hardcoded logoutSuccessUrl("https://localhost:443/"),
            // which sent EVERY user (ECWS or ELCM) to ELCM's page after logout,
            // since nginx's "/" location redirects to /elcm/dashboard unconditionally.
            // Now accepts an allow-listed ?post_logout_redirect_uri= param so each
            // app can send its own users back to itself; falls back to the old
            // behavior if the param is missing or not on the allow-list.
            .logoutSuccessHandler(postLogoutRedirectHandler())
            .invalidateHttpSession(true)
            // Fix #5: was .deleteCookies("SSOSESSIONID") -- that name doesn't
            // appear configured anywhere in the files reviewed, so it likely
            // wasn't clearing the real session cookie. Clearing both the
            // Spring Boot default (JSESSIONID) and SSOSESSIONID as a
            // belt-and-suspenders fix -- deleting a cookie that doesn't exist
            // is harmless. Replace with whatever server.servlet.session.cookie.name
            // is actually set in THIS app's own application.yml/properties
            // (not reviewed here) once confirmed.
            .deleteCookies("JSESSIONID", "SSOSESSIONID")
        );

    return httpSecurity.build();
  }

  private LogoutSuccessHandler postLogoutRedirectHandler() {
    return (request, response, authentication) -> {
      String requested = request.getParameter("post_logout_redirect_uri");
      String target = (requested != null && ALLOWED_POST_LOGOUT_REDIRECTS.contains(requested))
          ? requested
          : DEFAULT_POST_LOGOUT_REDIRECT;
      if (requested != null && !target.equals(requested)) {
        log.warn("Rejected post_logout_redirect_uri not on the allow-list: {}", requested);
      }
      response.sendRedirect(target);
    };
  }

  // Fix #3: Automatic Retry Logic for Expired Authorization Requests
  private AuthenticationFailureHandler createAuthenticationFailureHandler() {
    return (request, response, exception) -> {
      if (exception.getMessage().contains("authorization_request_not_found") ||
          (exception.getCause() != null &&
              exception.getCause().getMessage().contains("authorization_request_not_found"))) {
        response.sendRedirect("/login?error=authorization_request_expired");
      } else {
        response.sendRedirect("/login?error=true");
      }
    };
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient jsfClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("jsf-primefaces-client")
        .clientSecret(passwordEncoder().encode("jsf-client-secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        //.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        //.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantTypes(grantTypes -> {
          grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
          grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
        })
        // Fix #6: previously had FIVE redirect URIs -- a bare
        // "https://localhost:443/login/oauth2/code/sso" with no app prefix
        // (unused by the actual flow, since Spring's oauth2Login always
        // generates the callback relative to each app's own context-path --
        // ELCM produces /elcm/login/oauth2/code/sso, ECWS produces
        // /ecws/login/oauth2/code/sso, automatically), plus redundant
        // no-port duplicates of the two real ones. Trimmed to exactly the
        // two URIs that ELCM's and ECWS's redirect-uri properties actually
        // use. If the ambiguous bare URI comes back, also remove the
        // corresponding "location /login/" block in nginx.conf -- it exists
        // only to route that now-removed URI.
        .redirectUri("https://localhost:443/elcm/login/oauth2/code/sso")
        .redirectUri("https://localhost:443/ecws/login/oauth2/code/sso")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .scope(OidcScopes.EMAIL)
        .scope("read")
        .scope("write")
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .requireProofKey(false)
            .build())
        .tokenSettings(TokenSettings.builder()
            // Keep access token slightly longer than session to allow for refresh
            //.accessTokenTimeToLive(Duration.ofMinutes(35))
            // Refresh token should be longer for better UX
            //.refreshTokenTimeToLive(Duration.ofHours(8))
            .accessTokenTimeToLive(Duration.ofMinutes(30))
            .refreshTokenTimeToLive(Duration.ofHours(30))
            .authorizationCodeTimeToLive(Duration.ofMinutes(5))
            .reuseRefreshTokens(false)
            .build())
        .build();

    return new InMemoryRegisteredClientRepository(jsfClient);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
        .issuer("https://localhost:8081")
        .build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Use BCrypt instead of NoOp
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    // Fix #7: was List.of("https://localhost:443") only. Browsers omit the
    // port from the Origin header when it's the scheme's default port (443
    // for HTTPS), so the actual Origin sent through nginx is
    // "https://localhost" without ":443" -- the old value would never
    // exact-match that, silently rejecting legitimate cross-origin requests.
    // Keeping both forms since it's cheap and avoids re-debugging this if
    // something ever connects on a non-default port.
    configuration.setAllowedOrigins(List.of("https://localhost", "https://localhost:443"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}