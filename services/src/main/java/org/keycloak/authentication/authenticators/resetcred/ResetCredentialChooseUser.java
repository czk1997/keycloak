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

package org.keycloak.authentication.authenticators.resetcred;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.authentication.authenticators.util.RecaptchaUtil;
import org.keycloak.authentication.forms.RegistrationRecaptcha;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.dom.saml.v2.ac.BooleanType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ResetCredentialChooseUser implements Authenticator, AuthenticatorFactory {
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";

    private static final Logger logger = Logger.getLogger(ResetCredentialChooseUser.class);

    public static final String PROVIDER_ID = "reset-credentials-choose-user";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

    public static final String CPATCHA_ENABLED = "captcha.enabled";

    public static final String SCRIPT_LINK = "scriptLink";
    public static final String SITE_VERIFY_LINK = "siteVerifyLink";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String existingUserId = context.getAuthenticationSession().getAuthNote(AbstractIdpAuthenticator.EXISTING_USER_INFO);
        if (existingUserId != null) {
            UserModel existingUser = AbstractIdpAuthenticator.getExistingUser(context.getSession(), context.getRealm(), context.getAuthenticationSession());

            logger.debugf("Forget-password triggered when reauthenticating user after first broker login. Prefilling reset-credential-choose-user screen with user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            Response challenge = context.form().createPasswordReset();
            context.challenge(challenge);
            return;
        }

        String actionTokenUserId = context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        if (actionTokenUserId != null) {
            UserModel existingUser = context.getSession().users().getUserById(context.getRealm(), actionTokenUserId);

            // Action token logics handles checks for user ID validity and user being enabled

            logger.debugf("Forget-password triggered when reauthenticating user after authentication via action token. Skipping reset-credential-choose-user screen and using user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            return;
        }

        RecaptchaUtil.authenticateRecaptcha(context);
        Response challenge = context.form().createPasswordReset();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        boolean captchaResult = RecaptchaUtil.validate(context);
        if (!captchaResult) {
            return;
        }
        String username = formData.getFirst("username");
        if (username == null || username.isEmpty()) {
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form()
                    .addError(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        username = username.trim();

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(realm, username);
        if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
            user = context.getSession().users().getUserByEmail(realm, username);
        }

        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        // we don't want people guessing usernames, so if there is a problem, just continue, but don't set the user
        // a null user will notify further executions, that this was a failure.
        if (user == null) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .error(Errors.USER_NOT_FOUND);
            context.clearUser();
        } else if (!user.isEnabled()) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .user(user).error(Errors.USER_DISABLED);
            context.clearUser();
        } else {
            context.setUser(user);
        }

        context.success();
    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Choose User";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Choose a user to reset credentials for";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    @Override
    public String getId() {
        return PROVIDER_ID;
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
