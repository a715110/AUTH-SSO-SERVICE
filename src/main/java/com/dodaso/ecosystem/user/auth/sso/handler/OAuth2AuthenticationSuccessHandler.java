package com.dodaso.ecosystem.user.auth.sso.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
  private final DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    log.info("Authentication successful for user: {}", authentication.getName());

    // Check if this is an OAuth2 authorization request
    String redirectUri = determineRedirectUrl(request, authentication);

    if (redirectUri != null) {
      log.debug("Redirecting to: {}", redirectUri);
      redirectStrategy.sendRedirect(request, response, redirectUri);
    }
  }

  private String determineRedirectUrl(HttpServletRequest request, Authentication authentication) {
    // Check if there's a saved OAuth2 authorization request
    HttpSession session = request.getSession(false);
    if (session != null) {
      Object savedRequest = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
      if (savedRequest instanceof DefaultSavedRequest) {
        DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) savedRequest;
        String originalUrl = defaultSavedRequest.getRedirectUrl();
        log.debug("Found saved request: {}", originalUrl);
        return originalUrl;
      }
    }

    // Default fallback - should trigger OAuth2 flow completion
    return "/";
  }
}