package com.dodaso.ecosystem.user.auth.sso.config;

import com.dodaso.ecosystem.baseline.common.config.DodasoInstanceProperties;
import com.dodaso.ecosystem.user.auth.sso.handler.OAuth2AuthenticationSuccessHandler;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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

/**
 * Authorization server configuration.
 *
 * <p><b>STEP1 (dedicated single-tenant):</b> nothing customer- or environment-specific
 * is hard-coded any more. The issuer, redirect URIs, logout allow-list, default logout
 * target, CORS origins and client secret come from {@link DodasoInstanceProperties}
 * (issuer, ECWS/ELCM base URLs) plus {@link SsoProperties} (secret and local extras).
 * Security behavior is otherwise unchanged.
 *
 * <p><b>Deferred to Step 2</b> (unchanged here on purpose):
 * <ul>
 *   <li>{@link #jwkSource()} generates a new signing key at every startup, so tokens
 *       issued before a restart become invalid and only one instance can run.</li>
 *   <li>Registered clients and authorizations are held in memory / H2.</li>
 *   <li>Both UIs share one client ({@code jsf-primefaces-client}).</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties({DodasoInstanceProperties.class, SsoProperties.class})
@RequiredArgsConstructor
@Slf4j
public class AuthServerConfig {

  /** Callback path Spring's oauth2Login generates under each UI's context path. */
  private static final String OAUTH2_CALLBACK_PATH = "/login/oauth2/code/sso";

  private final OAuth2AuthenticationSuccessHandler authenticationSuccessHandler;
  private final DodasoInstanceProperties instance;
  private final SsoProperties sso;

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
            // STEP1: container liveness/readiness probes and version check (Step 6)
            .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/login")
            // Sends users to the app launcher after login, but ONLY when there is no
            // bookmarked deep link to replay ("false"): saved-request replay still wins.
            .defaultSuccessUrl("/apps", false)
            .permitAll()
        ).logout(l -> l
            .logoutUrl("/logout")
            // Allow-listed ?post_logout_redirect_uri= so each app sends its users back
            // to itself; falls back to the default target otherwise.
            .logoutSuccessHandler(postLogoutRedirectHandler())
            .invalidateHttpSession(true)
            // SSOSESSIONID is this server's configured cookie name
            // (server.servlet.session.cookie.name); JSESSIONID kept as a harmless fallback.
            .deleteCookies("SSOSESSIONID", "JSESSIONID")
        );

    return httpSecurity.build();
  }

  /**
   * Exact-match allow-list only. Do NOT switch to prefix/contains matching or
   * URI-parsing-based validation: both are common open-redirect footguns.
   * Allowed: {ELCM base}/ and {ECWS base}/ for this instance, plus local extras.
   */
  private LogoutSuccessHandler postLogoutRedirectHandler() {
    final Set<String> allowed = new LinkedHashSet<>();
    allowed.add(instance.elcmBaseUrl() + "/");
    allowed.add(instance.ecwsBaseUrl() + "/");
    allowed.addAll(sso.extraPostLogoutRedirects());
    final Set<String> allowList = Set.copyOf(allowed);

    final String defaultTarget = sso.defaultPostLogoutRedirect().isBlank()
        ? instance.elcmBaseUrl() + "/"
        : sso.defaultPostLogoutRedirect();

    log.info("Post-logout redirect allow-list: {} (default: {})", allowList, defaultTarget);

    return (request, response, authentication) -> {
      String requested = request.getParameter("post_logout_redirect_uri");
      String target = (requested != null && allowList.contains(requested))
          ? requested
          : defaultTarget;
      if (requested != null && !target.equals(requested)) {
        log.warn("Rejected post_logout_redirect_uri not on the allow-list: {}", requested);
      }
      response.sendRedirect(target);
    };
  }

  // Automatic retry logic for expired authorization requests (currently not wired in)
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
    // Exact-match redirect URIs: {UI base URL} + callback path for each UI, plus
    // local extras (the ":443" spellings the local UIs are still configured with).
    final Set<String> redirectUris = new LinkedHashSet<>();
    redirectUris.add(instance.elcmBaseUrl() + OAUTH2_CALLBACK_PATH);
    redirectUris.add(instance.ecwsBaseUrl() + OAUTH2_CALLBACK_PATH);
    redirectUris.addAll(sso.extraRedirectUris());
    log.info("Registered client '{}' redirect URIs: {}", sso.clientId(), redirectUris);

    RegisteredClient jsfClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId(sso.clientId())
        .clientSecret(passwordEncoder().encode(sso.clientSecret()))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantTypes(grantTypes -> {
          grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
          grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
        })
        .redirectUris(uris -> uris.addAll(redirectUris))
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
    // STEP1: was hard-coded "https://localhost:8081"
    return AuthorizationServerSettings.builder()
        .issuer(instance.authIssuerUri())
        .build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  /**
   * Signing key. Persistent across restarts: from Key Vault in the cloud (jwk-private-key) or a
   * local PEM file in development (jwk-key-file). See {@link JwkKeyProvider}.
   */
  @Bean
  public JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource() {
    RSAKey rsaKey = JwkKeyProvider.resolve(sso.jwkPrivateKey(), sso.jwkKeyFile());
    log.info("Authorization server signing key loaded, kid={}", rsaKey.getKeyID());
    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    // Origins of this instance's UIs (scheme://host[:port], default port omitted the way
    // browsers send it), plus local extras such as "https://localhost:443".
    final Set<String> origins = new LinkedHashSet<>();
    origins.add(originOf(instance.elcmBaseUrl()));
    origins.add(originOf(instance.ecwsBaseUrl()));
    origins.addAll(sso.extraCorsOrigins());
    log.info("CORS allowed origins: {}", origins);

    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(new ArrayList<>(origins));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  /** "https://acme.dodaso.app/elcm" -> "https://acme.dodaso.app"; keeps a non-default port. */
  private static String originOf(String baseUrl) {
    URI uri = URI.create(baseUrl);
    boolean defaultPort = uri.getPort() == -1
        || ("https".equals(uri.getScheme()) && uri.getPort() == 443)
        || ("http".equals(uri.getScheme()) && uri.getPort() == 80);
    return uri.getScheme() + "://" + uri.getHost() + (defaultPort ? "" : ":" + uri.getPort());
  }
}
