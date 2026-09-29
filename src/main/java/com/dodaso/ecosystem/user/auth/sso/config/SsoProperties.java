package com.dodaso.ecosystem.user.auth.sso.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Authorization-server settings that vary per customer instance or per environment.
 * Bound from {@code dodaso.sso.*}.
 *
 * <p>Everything that can be derived from the instance identity
 * ({@code DodasoInstanceProperties}: issuer, ECWS and ELCM base URLs) is derived in
 * {@link AuthServerConfig}. The lists here only ADD values on top of the derived ones,
 * e.g. the local ":443" spellings that the local UIs still use. In a customer instance
 * they are normally empty.
 */
@Validated
@ConfigurationProperties(prefix = "dodaso.sso")
public record SsoProperties(

        /** OAuth2 client id shared by both UIs until Step 2 registers one client per UI. */
        @DefaultValue("jsf-primefaces-client")
        @NotBlank
        String clientId,

        /** Plain-text client secret (encoded with BCrypt at startup). From Key Vault in the cloud. */
        @NotBlank
        String clientSecret,

        /** Extra exact-match redirect URIs, in addition to {base-url}/login/oauth2/code/sso per UI. */
        @DefaultValue({})
        List<String> extraRedirectUris,

        /** Extra exact-match post-logout targets, in addition to {base-url}/ per UI. */
        @DefaultValue({})
        List<String> extraPostLogoutRedirects,

        /** Where logout goes when no allowed post_logout_redirect_uri is given. Blank = ELCM base URL + "/". */
        @DefaultValue("")
        @Pattern(regexp = "^$|^https://.+", message = "default-post-logout-redirect must be blank or an https URL")
        String defaultPostLogoutRedirect,

        /** Extra CORS origins, in addition to the origins of the ECWS and ELCM base URLs. */
        @DefaultValue({})
        List<String> extraCorsOrigins
) {
}
