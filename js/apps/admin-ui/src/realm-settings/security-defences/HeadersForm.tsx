import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { ActionGroup, Button } from "@patternfly/react-core";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormAccess } from "../../components/form/FormAccess";
import { HelpLinkTextInput } from "./HelpLinkTextInput";

import "./security-defences.css";

type HeadersFormProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

const REFERRER_POLICY_VALUES = [
  "",
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
];

export const HeadersForm = ({ realm, save }: HeadersFormProps) => {
  const { t } = useTranslation();
  const form = useFormContext<RealmRepresentation>();
  const {
    reset,
    formState: { isDirty },
    handleSubmit,
  } = form;

  return (
    <FormAccess
      isHorizontal
      role="manage-realm"
      className="keycloak__security-defences__form"
      onSubmit={handleSubmit(save)}
    >
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.xFrameOptions"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            const v = value.trim().toUpperCase();
            if (
              v === "DENY" ||
              v === "SAMEORIGIN" ||
              v.startsWith("ALLOW-FROM ")
            ) {
              return true;
            }
            return t("invalidXFrameOptionsValue");
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.contentSecurityPolicy"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            if (/[\n\r\0]/.test(value)) {
              return t("invalidHeaderContainsNewline");
            }
            return true;
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.contentSecurityPolicyReportOnly"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            if (/[\n\r\0]/.test(value)) {
              return t("invalidHeaderContainsNewline");
            }
            return true;
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.xContentTypeOptions"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            if (value.trim().toLowerCase() !== "nosniff") {
              return t("invalidXContentTypeOptionsValue");
            }
            return true;
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.xRobotsTag"
        url="https://developers.google.com/search/docs/advanced/robots/robots_meta_tag"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            const validDirectives = [
              "all",
              "noindex",
              "nofollow",
              "none",
              "nosnippet",
              "noarchive",
              "nocache",
              "noimageindex",
              "notranslate",
              "indexifembedded",
            ];
            const directives = value
              .toLowerCase()
              .split(",")
              .map((d) => d.trim());
            for (const directive of directives) {
              // Allow max-snippet:N, max-image-preview:value, max-video-preview:N, unavailable_after:date
              if (
                /^max-snippet:-?\d+$/.test(directive) ||
                /^max-image-preview:(none|standard|large)$/.test(directive) ||
                /^max-video-preview:-?\d+$/.test(directive) ||
                /^unavailable_after:.+$/.test(directive)
              ) {
                continue;
              }
              if (!validDirectives.includes(directive)) {
                return t("invalidXRobotsTagValue");
              }
            }
            return true;
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.strictTransportSecurity"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            const v = value.trim().toLowerCase();
            // Must contain max-age directive with non-negative integer
            if (!/max-age=\d+/.test(v)) {
              return t("invalidStrictTransportSecurityValue");
            }
            // Only allow valid directives: max-age, includeSubDomains, preload
            const parts = v.split(";").map((p) => p.trim());
            for (const part of parts) {
              if (!part) continue;
              if (
                !/^max-age=\d+$/.test(part) &&
                part !== "includesubdomains" &&
                part !== "preload"
              ) {
                return t("invalidStrictTransportSecurityValue");
              }
            }
            return true;
          },
        }}
      />
      <HelpLinkTextInput
        fieldName="browserSecurityHeaders.referrerPolicy"
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        rules={{
          validate: (value: string) => {
            if (!value) return true;
            if (!REFERRER_POLICY_VALUES.includes(value.trim().toLowerCase())) {
              return t("invalidReferrerPolicyValue");
            }
            return true;
          },
        }}
      />

      <ActionGroup>
        <Button
          variant="primary"
          type="submit"
          data-testid="headers-form-tab-save"
          isDisabled={!isDirty}
        >
          {t("save")}
        </Button>
        <Button variant="link" onClick={() => reset(realm)}>
          {t("revert")}
        </Button>
      </ActionGroup>
    </FormAccess>
  );
};
