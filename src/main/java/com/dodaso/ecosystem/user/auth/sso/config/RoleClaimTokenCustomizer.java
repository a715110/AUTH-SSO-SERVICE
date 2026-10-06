package com.dodaso.ecosystem.user.auth.sso.config;

import com.dodaso.ecosystem.user.auth.sso.service.SsoUserDetails;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Adds a "roles" claim (IAMS role names as stored, e.g. ["Super Admin"]) to the
 * access token and the ID token, so a client such as ELCM can read the user's
 * roles from its login session without calling IAMS.
 *
 * The claim is a snapshot taken at login: a role change shows up after the user
 * signs in again (and for a refreshed token, when the token is reissued from the
 * stored login). When the principal carries no role data the claim is omitted,
 * and clients fall back to asking IAMS.
 */
@Component
@Slf4j
public class RoleClaimTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  /** Claim name read by the clients. */
  public static final String ROLES_CLAIM = "roles";

  @Override
  public void customize(JwtEncodingContext context) {
    final String tokenType = context.getTokenType().getValue();
    final boolean accessToken = OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType);
    final boolean idToken = OidcParameterNames.ID_TOKEN.equals(tokenType);
    if (!accessToken && !idToken) {
      return;
    }
    final Authentication principal = context.getPrincipal();
    if (principal != null && principal.getPrincipal() instanceof SsoUserDetails user) {
      final List<String> roles = user.getRoleNames();
      context.getClaims().claim(ROLES_CLAIM, roles);
      log.debug("Added roles claim for {}: {}", user.getUsername(), roles);
    }
  }
}
