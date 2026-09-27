package com.dodaso.ecosystem.user.auth.sso.launcher;

/**
 * One entry in the post-login application launcher panel.
 *
 * requiredAuthority is intentionally nullable: leave it null and every
 * logged-in user sees the entry (today's behavior -- same static list for
 * everyone). Set it to a Spring Security authority/role name (e.g.
 * "ROLE_ELCM_USER") once per-app access control is ready, and
 * AppLauncherController will start filtering automatically -- no code
 * change needed there when that day comes.
 */
public record AppEntry(
    String name,
    String description,
    String iconUrl,
    String url,
    String requiredAuthority
) {
  public boolean isVisibleTo(java.util.Set<String> userAuthorities) {
    return requiredAuthority == null || requiredAuthority.isBlank()
        || userAuthorities.contains(requiredAuthority);
  }
}