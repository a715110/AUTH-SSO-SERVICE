package com.dodaso.ecosystem.user.auth.sso.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

@Configuration
public class DebugConfig {
  @EventListener
  public void handleContextRefresh(ContextRefreshedEvent event) {
    Environment env = event.getApplicationContext().getEnvironment();
    String port = env.getProperty("server.port");
    String sslEnabled = env.getProperty("server.ssl.enabled");
    String issuer = env.getProperty("spring.security.oauth2.authorizationserver.issuer");

    System.out.println("=== Authorization Server Configuration ===");
    System.out.println("Server Port: " + port);
    System.out.println("SSL Enabled: " + sslEnabled);
    System.out.println("Issuer: " + issuer);
    System.out.println("==========================================");
  }
}