package com.dodaso.ecosystem.user.auth.sso.service;

import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Spring Security user that also keeps the IAMS role names exactly as stored
 * (for example "Super Admin"). The authorities hold the normalized form
 * (ROLE_SUPER_ADMIN), which cannot be turned back into the original name, and
 * the token customizer needs the original so apps can match it against IAMS
 * data such as page_access.
 */
public class SsoUserDetails extends User {

  private static final long serialVersionUID = 1L;

  private final List<String> roleNames;

  /** ADDED 2026-11-11: the name shown on the app launcher. May be null; then the login id is used. */
  private final String displayName;

  public SsoUserDetails(String username, String password,
      Collection<? extends GrantedAuthority> authorities, List<String> roleNames) {
    this(username, password, authorities, roleNames, null);
  }

  public SsoUserDetails(String username, String password,
      Collection<? extends GrantedAuthority> authorities, List<String> roleNames,
      String displayName) {
    super(username, password, true, true, true, true, authorities);
    this.roleNames = roleNames == null ? List.of() : List.copyOf(roleNames);
    this.displayName = displayName == null || displayName.isBlank() ? null : displayName.trim();
  }

  /** The person's display name from the IAMS directory, or null when it is not known. */
  public String getDisplayName() {
    return displayName;
  }

  /** IAMS role names as stored, in directory order. Never null. */
  public List<String> getRoleNames() {
    return roleNames;
  }
}
