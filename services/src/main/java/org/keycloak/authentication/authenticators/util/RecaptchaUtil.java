package org.keycloak.authentication.authenticators.util;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.dom.saml.v2.ac.BooleanType;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class RecaptchaUtil {
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String SCRIPT_LINK = "scriptLink";
    public static final String SITE_VERIFY_LINK = "siteVerifyLink";
    public static final String CPATCHA_ENABLED = "captcha.enabled";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

    public static void authenticateRecaptcha(AuthenticationFlowContext context) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        LoginFormsProvider form = context.form();
        if (captchaConfig == null || captchaConfig.getConfig() == null) {
            return;
        }
        String captchaEnabled = captchaConfig.getConfig().get(CPATCHA_ENABLED);
        if (BooleanType.TRUE.value().equals(captchaEnabled)) {
            if (captchaConfig.getConfig().get(SITE_KEY) == null
                    || captchaConfig.getConfig().get(SITE_SECRET) == null) {
                form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
                //TODO missing key challange
                return;
            }
            String siteKey = captchaConfig.getConfig().get(SITE_KEY);
            String scriptLink = captchaConfig.getConfig().get(SCRIPT_LINK);
            form.setAttribute("recaptchaRequired", true);
            form.setAttribute("recaptchaSiteKey", siteKey);
            form.addScript(scriptLink);
        }

    }

    public static boolean validate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String enabled = captchaConfig.getConfig().get(CPATCHA_ENABLED);
        if (enabled == null || BooleanType.FALSE.value().equals(enabled)) {
            return true;
        }
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");
        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            String secret = captchaConfig.getConfig().get(SITE_SECRET);
            success = validateRecaptcha(context, success, captcha, secret);
        }
        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(G_RECAPTCHA_RESPONSE);
        }
        return success;
    }

    protected static boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String siteVerifyLink = captchaConfig.getConfig().get(SITE_VERIFY_LINK);
        CloseableHttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost(siteVerifyLink);
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();
                try {
                    Map json = JsonSerialization.readValue(content, Map.class);
                    Object val = json.get("success");
                    success = Boolean.TRUE.equals(val);
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }
}
