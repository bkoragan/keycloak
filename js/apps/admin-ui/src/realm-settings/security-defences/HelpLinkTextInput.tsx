import { Trans, useTranslation } from "react-i18next";
import { TextControl } from "@keycloak/keycloak-ui-shared";
import { FormattedLink } from "../../components/external-link/FormattedLink";
import type { RegisterOptions } from "react-hook-form";

type HelpLinkTextInputProps = {
  fieldName: string;
  url: string;
  rules?: RegisterOptions;
};

export const HelpLinkTextInput = ({
  fieldName,
  url,
  rules,
}: HelpLinkTextInputProps) => {
  const { t } = useTranslation();
  const name = fieldName.substring(fieldName.indexOf(".") + 1);
  return (
    <TextControl
      name={fieldName}
      label={t(name)}
      labelIcon={
        <Trans
          i18nKey={`${name}Help`}
          components={{
            formattedlink: <FormattedLink href={url} title={t("learnMore")} />,
          }}
        />
      }
      rules={rules}
    />
  );
};
