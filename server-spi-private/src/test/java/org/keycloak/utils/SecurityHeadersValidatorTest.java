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

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.BadRequestException;

import org.junit.Test;

public class SecurityHeadersValidatorTest {

    @Test
    public void testNullHeadersAccepted() {
        SecurityHeadersValidator.validate(null);
    }

    @Test
    public void testEmptyHeadersAccepted() {
        SecurityHeadersValidator.validate(new HashMap<>());
    }

    // X-Frame-Options tests

    @Test
    public void testXFrameOptionsDeny() {
        Map<String, String> headers = Map.of("xFrameOptions", "DENY");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXFrameOptionsSameOrigin() {
        Map<String, String> headers = Map.of("xFrameOptions", "SAMEORIGIN");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXFrameOptionsAllowFrom() {
        Map<String, String> headers = Map.of("xFrameOptions", "ALLOW-FROM https://example.com");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXFrameOptionsCaseInsensitive() {
        Map<String, String> headers = Map.of("xFrameOptions", "deny");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testXFrameOptionsInvalid() {
        Map<String, String> headers = Map.of("xFrameOptions", "INVALID");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXFrameOptionsEmpty() {
        Map<String, String> headers = Map.of("xFrameOptions", "");
        SecurityHeadersValidator.validate(headers);
    }

    // X-Content-Type-Options tests

    @Test
    public void testXContentTypeOptionsNosniff() {
        Map<String, String> headers = Map.of("xContentTypeOptions", "nosniff");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXContentTypeOptionsCaseInsensitive() {
        Map<String, String> headers = Map.of("xContentTypeOptions", "NOSNIFF");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testXContentTypeOptionsInvalid() {
        Map<String, String> headers = Map.of("xContentTypeOptions", "sniff");
        SecurityHeadersValidator.validate(headers);
    }

    // X-Robots-Tag tests

    @Test
    public void testXRobotsTagNone() {
        Map<String, String> headers = Map.of("xRobotsTag", "none");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXRobotsTagMultipleDirectives() {
        Map<String, String> headers = Map.of("xRobotsTag", "noindex, nofollow");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXRobotsTagMaxSnippet() {
        Map<String, String> headers = Map.of("xRobotsTag", "max-snippet:50");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testXRobotsTagMaxImagePreview() {
        Map<String, String> headers = Map.of("xRobotsTag", "max-image-preview:large");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testXRobotsTagInvalid() {
        Map<String, String> headers = Map.of("xRobotsTag", "invalidDirective");
        SecurityHeadersValidator.validate(headers);
    }

    // Strict-Transport-Security tests

    @Test
    public void testHstsDefault() {
        Map<String, String> headers = Map.of("strictTransportSecurity", "max-age=31536000; includeSubDomains");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testHstsWithPreload() {
        Map<String, String> headers = Map.of("strictTransportSecurity", "max-age=31536000; includeSubDomains; preload");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testHstsMaxAgeOnly() {
        Map<String, String> headers = Map.of("strictTransportSecurity", "max-age=0");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testHstsMissingMaxAge() {
        Map<String, String> headers = Map.of("strictTransportSecurity", "includeSubDomains");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testHstsInvalidDirective() {
        Map<String, String> headers = Map.of("strictTransportSecurity", "max-age=31536000; invalidDirective");
        SecurityHeadersValidator.validate(headers);
    }

    // Referrer-Policy tests

    @Test
    public void testReferrerPolicyNoReferrer() {
        Map<String, String> headers = Map.of("referrerPolicy", "no-referrer");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testReferrerPolicyStrictOriginWhenCrossOrigin() {
        Map<String, String> headers = Map.of("referrerPolicy", "strict-origin-when-cross-origin");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testReferrerPolicyInvalid() {
        Map<String, String> headers = Map.of("referrerPolicy", "invalid-policy");
        SecurityHeadersValidator.validate(headers);
    }

    // Newline injection tests

    @Test(expected = BadRequestException.class)
    public void testNewlineInHeaderValue() {
        Map<String, String> headers = Map.of("xFrameOptions", "DENY\nX-Injected: true");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testCarriageReturnInHeaderValue() {
        Map<String, String> headers = Map.of("referrerPolicy", "no-referrer\rX-Injected: true");
        SecurityHeadersValidator.validate(headers);
    }

    @Test(expected = BadRequestException.class)
    public void testNullByteInHeaderValue() {
        Map<String, String> headers = Map.of("contentSecurityPolicy", "default-src 'self'\0injected");
        SecurityHeadersValidator.validate(headers);
    }

    // CSP tests (only newline validation)

    @Test
    public void testCspValidValue() {
        Map<String, String> headers = Map.of("contentSecurityPolicy",
                "frame-src 'self'; frame-ancestors 'self'; object-src 'none';");
        SecurityHeadersValidator.validate(headers);
    }

    @Test
    public void testCspReportOnlyEmpty() {
        Map<String, String> headers = Map.of("contentSecurityPolicyReportOnly", "");
        SecurityHeadersValidator.validate(headers);
    }

    // Combined headers test

    @Test
    public void testAllDefaultHeadersValid() {
        Map<String, String> headers = new HashMap<>();
        headers.put("xFrameOptions", "SAMEORIGIN");
        headers.put("contentSecurityPolicy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';");
        headers.put("contentSecurityPolicyReportOnly", "");
        headers.put("xContentTypeOptions", "nosniff");
        headers.put("xRobotsTag", "none");
        headers.put("strictTransportSecurity", "max-age=31536000; includeSubDomains");
        headers.put("referrerPolicy", "no-referrer");
        SecurityHeadersValidator.validate(headers);
    }
}
