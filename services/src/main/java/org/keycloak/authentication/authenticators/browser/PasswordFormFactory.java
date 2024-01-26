/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PasswordFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-password-form";
    public static final PasswordForm SINGLETON = new PasswordForm();
    public static final String SCRIPT_LINK = "scriptLink";
    public static final String SITE_VERIFY_LINK = "siteVerifyLink";
    public static final String CPATCHA_ENABLED = "captcha.enabled";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a password from login form.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(CPATCHA_ENABLED);
        property.setLabel("Captcha Enabled");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue("false");
        property.setHelpText("Enable Captcha to verify the user is human");
        CONFIG_PROPERTIES.add(property);


        property = new ProviderConfigProperty();
        property.setName(SITE_KEY);
        property.setLabel("Captcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Captcha Site Key");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(SITE_SECRET);
        property.setLabel("Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Captcha Secret");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(SCRIPT_LINK);
        property.setLabel("Script URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("");
        property.setHelpText("The script that rendered in the client-end");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(SITE_VERIFY_LINK);
        property.setLabel("Site Verify URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("");
        property.setHelpText("The URL used in the server-end to verify the captcha");
        CONFIG_PROPERTIES.add(property);
    }
}
