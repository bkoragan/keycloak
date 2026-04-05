/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.utils;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import jakarta.ws.rs.BadRequestException;

import org.keycloak.models.BrowserSecurityHeaders;

/**
 * Validates browser security header values according to their respective HTTP specifications.
 *
 * @see BrowserSecurityHeaders
 */
public class SecurityHeadersValidator {

    private static final Pattern NEWLINE_PATTERN = Pattern.compile("[\\n\\r\\0]");

    private static final Set<String> VALID_X_FRAME_OPTIONS_VALUES = Set.of("DENY", "SAMEORIGIN");

    private static final Set<String> VALID_REFERRER_POLICY_VALUES = Set.of(
            "", "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url"
    );

    private static final Set<String> VALID_ROBOTS_DIRECTIVES = Set.of(
            "all", "noindex", "nofollow", "none", "nosnippet", "noarchive",
            "nocache", "noimageindex", "notranslate", "indexifembedded"
    );

    private static final Pattern HSTS_MAX_AGE_PATTERN = Pattern.compile("max-age=\\d+");
    private static final Pattern HSTS_DIRECTIVE_PATTERN = Pattern.compile("^max-age=\\d+$");
    private static final Pattern ROBOTS_MAX_SNIPPET = Pattern.compile("^max-snippet:-?\\d+$");
    private static final Pattern ROBOTS_MAX_IMAGE_PREVIEW = Pattern.compile("^max-image-preview:(none|standard|large)$");
    private static final Pattern ROBOTS_MAX_VIDEO_PREVIEW = Pattern.compile("^max-video-preview:-?\\d+$");
    private static final Pattern ROBOTS_UNAVAILABLE_AFTER = Pattern.compile("^unavailable_after:.+$");

    private SecurityHeadersValidator() {
    }

    /**
     * Validates all browser security headers in the given map.
     *
     * @param headers map of header keys to values (using BrowserSecurityHeaders keys)
     * @throws BadRequestException if any header value is invalid
     */
    public static void validate(Map<String, String> headers) {
        if (headers == null) return;

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Common validation: no newlines or null bytes in any header
            validateNoNewlines(key, "Header key");
            validateNoNewlines(value, "Header value");

            // Header-specific validation
            if (BrowserSecurityHeaders.X_FRAME_OPTIONS.getKey().equals(key)) {
                validateXFrameOptions(value);
            } else if (BrowserSecurityHeaders.X_CONTENT_TYPE_OPTIONS.getKey().equals(key)) {
                validateXContentTypeOptions(value);
            } else if (BrowserSecurityHeaders.X_ROBOTS_TAG.getKey().equals(key)) {
                validateXRobotsTag(value);
            } else if (BrowserSecurityHeaders.STRICT_TRANSPORT_SECURITY.getKey().equals(key)) {
                validateStrictTransportSecurity(value);
            } else if (BrowserSecurityHeaders.REFERRER_POLICY.getKey().equals(key)) {
                validateReferrerPolicy(value);
            }
            // CSP and CSP-Report-Only have flexible directive syntax; only newline validation applies
        }
    }

    static void validateNoNewlines(String value, String fieldName) {
        if (value != null && NEWLINE_PATTERN.matcher(value).find()) {
            throw new BadRequestException(fieldName + " must not contain newline characters.");
        }
    }

    /**
     * X-Frame-Options must be DENY, SAMEORIGIN, or ALLOW-FROM uri.
     * See RFC 7034.
     */
    static void validateXFrameOptions(String value) {
        if (value == null || value.isEmpty()) return;
        String upper = value.trim().toUpperCase();
        if (VALID_X_FRAME_OPTIONS_VALUES.contains(upper) || upper.startsWith("ALLOW-FROM ")) {
            return;
        }
        throw new BadRequestException(
                "Invalid X-Frame-Options value. Must be \"DENY\", \"SAMEORIGIN\", or \"ALLOW-FROM <uri>\".");
    }

    /**
     * X-Content-Type-Options only allows "nosniff".
     */
    static void validateXContentTypeOptions(String value) {
        if (value == null || value.isEmpty()) return;
        if (!"nosniff".equalsIgnoreCase(value.trim())) {
            throw new BadRequestException("Invalid X-Content-Type-Options value. Must be \"nosniff\".");
        }
    }

    /**
     * X-Robots-Tag must contain valid directives.
     * See https://developers.google.com/search/docs/advanced/robots/robots_meta_tag
     */
    static void validateXRobotsTag(String value) {
        if (value == null || value.isEmpty()) return;
        String[] directives = value.toLowerCase().split(",");
        for (String directive : directives) {
            String d = directive.trim();
            if (d.isEmpty()) continue;
            if (VALID_ROBOTS_DIRECTIVES.contains(d)) continue;
            if (ROBOTS_MAX_SNIPPET.matcher(d).matches()) continue;
            if (ROBOTS_MAX_IMAGE_PREVIEW.matcher(d).matches()) continue;
            if (ROBOTS_MAX_VIDEO_PREVIEW.matcher(d).matches()) continue;
            if (ROBOTS_UNAVAILABLE_AFTER.matcher(d).matches()) continue;
            throw new BadRequestException(
                    "Invalid X-Robots-Tag directive: \"" + directive.trim() + "\".");
        }
    }

    /**
     * Strict-Transport-Security must contain max-age=seconds, optionally with includeSubDomains and preload.
     * See RFC 6797.
     */
    static void validateStrictTransportSecurity(String value) {
        if (value == null || value.isEmpty()) return;
        String lower = value.trim().toLowerCase();
        if (!HSTS_MAX_AGE_PATTERN.matcher(lower).find()) {
            throw new BadRequestException(
                    "Invalid Strict-Transport-Security value. Must contain \"max-age=<seconds>\".");
        }
        String[] parts = lower.split(";");
        for (String part : parts) {
            String p = part.trim();
            if (p.isEmpty()) continue;
            if (HSTS_DIRECTIVE_PATTERN.matcher(p).matches()) continue;
            if ("includesubdomains".equals(p)) continue;
            if ("preload".equals(p)) continue;
            throw new BadRequestException(
                    "Invalid Strict-Transport-Security directive: \"" + part.trim()
                            + "\". Only max-age, includeSubDomains, and preload are allowed.");
        }
    }

    /**
     * Referrer-Policy must be one of the spec-defined values.
     * See https://www.w3.org/TR/referrer-policy/
     */
    static void validateReferrerPolicy(String value) {
        if (value == null || value.isEmpty()) return;
        if (!VALID_REFERRER_POLICY_VALUES.contains(value.trim().toLowerCase())) {
            throw new BadRequestException(
                    "Invalid Referrer-Policy value: \"" + value
                            + "\". Must be one of: no-referrer, no-referrer-when-downgrade, origin, "
                            + "origin-when-cross-origin, same-origin, strict-origin, "
                            + "strict-origin-when-cross-origin, unsafe-url.");
        }
    }
}
