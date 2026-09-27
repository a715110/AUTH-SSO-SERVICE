package com.dodaso.ecosystem.user.auth.sso.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class LoginController {

  @GetMapping("/login")
  public String login(Model model, HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    System.out.println(model);
    System.out.println(request);
//
//    // Handle OAuth2 authorization request expiration scenarios
    //   String error = request.getParameter("error");
//    String retry = request.getParameter("retry");
//    String autosubmit = request.getParameter("autosubmit");
//
//    if (error != null) {
//      if ("true".equals(error)) {
//        model.addAttribute("error", "Invalid username or password");
//      } //else {
//        // Handle specific OAuth2 errors
//        if (error.contains("authorization_request_not_found")) {
//          log.warn("OAuth2 authorization request expired, redirecting to fresh flow");
//          // Redirect to fresh OAuth2 flow instead of showing error
//          response.sendRedirect("/oauth2/authorize?client_id=jsf-primefaces-client&response_type=code&redirect_uri=https://localhost:443/login/oauth2/code/sso&scope=openid");
//          return null;
//        }
//        model.addAttribute("error", "Authentication failed. Please try again.");
//      }
//    }
//
//    // Check if this is an automatic retry due to expired authorization request
//    if (retry != null) {
//      log.info("Automatic retry detected due to expired authorization request");
//      model.addAttribute("message", "Session expired. Please login again.");
//    }
//
//    // Check if user was logged out
//    String logout = request.getParameter("logout");
//    if (logout != null) {
//      model.addAttribute("message", "You have been logged out successfully");
//    }
//
//    // Add session expiration detection
//    String expired = request.getParameter("expired");
//    if (expired != null) {
//      model.addAttribute("message", "Your session has expired. Please login again.");
//    }
//
    return "login";
  }
//
//  // Handle OAuth2 authorization errors specifically
//  @GetMapping("/login/oauth2/error")
//  public String handleOAuth2Error(HttpServletRequest request, Model model, HttpServletResponse response) throws IOException {
//    String error = request.getParameter("error");
//    String errorDescription = request.getParameter("error_description");
//
//    log.warn("OAuth2 error: {} - {}", error, errorDescription);
//
//    if ("authorization_request_not_found".equals(error)) {
//      log.info("Handling authorization_request_not_found - redirecting to fresh OAuth2 flow");
//      // Instead of showing error, redirect to fresh OAuth2 flow
//      response.sendRedirect("/oauth2/authorize?client_id=jsf-primefaces-client&response_type=code&redirect_uri=https://localhost:443/login/oauth2/code/sso&scope=openid&retry=" + System.currentTimeMillis());
//      return null;
//    }
//
//    // For other errors, show the login page with error message
//    model.addAttribute("error", "Authentication failed: " + (errorDescription != null ? errorDescription : error));
//    return "login";
//  }
//
//  // Handle session timeout scenarios
//  @GetMapping("/login/session-expired")
//  public String handleSessionExpired(Model model) {
//    log.info("Session expired, showing login page");
//    model.addAttribute("message", "Your session has expired due to inactivity. Please login again.");
//    return "login";
//  }
}