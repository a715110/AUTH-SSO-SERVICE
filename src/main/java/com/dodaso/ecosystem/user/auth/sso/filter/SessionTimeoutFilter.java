package com.dodaso.ecosystem.user.auth.sso.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

// Create a session timeout filter
@Component
@Order(1)
public class SessionTimeoutFilter extends OncePerRequestFilter {
  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    HttpSession session = request.getSession(false);
    if (session != null) {
      // Check if session is about to expire or has been inactive
      long lastAccessed = session.getLastAccessedTime();
      long maxInactive = session.getMaxInactiveInterval() * 1000L;
      long now = System.currentTimeMillis();

      if (now - lastAccessed > maxInactive) {
        // Mark session as timed out before invalidating
        session.setAttribute("sessionTimedOut", true);
      }
    }

    filterChain.doFilter(request, response);
  }
}