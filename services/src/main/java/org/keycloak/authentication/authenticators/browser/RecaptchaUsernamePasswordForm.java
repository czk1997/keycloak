package org.keycloak.authentication.authenticators.browser;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.forms.RegistrationRecaptcha;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.io.InputStream;
import java.util.*;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";
    private static final Logger logger = Logger.getLogger(RecaptchaUsernamePasswordForm.class);

    private String siteKey;

    public static final String RECAPTCHA_REFERENCE_CATEGORY = "recaptcha";


    public static final String PROVIDER_ID = "registration-recaptcha-action";
    public static final String SCRIPT_LINK = "scriptLink";
    public static final String SITE_VERIFY_LINK = "siteVerifyLink";

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        return super.createLoginForm(form);
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form, AuthenticationFlowContext context) {
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String scriptLink = captchaConfig.getConfig().get(SCRIPT_LINK);
        form.addScript(scriptLink);
        return super.createLoginForm(form);
    }


    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (logger.isInfoEnabled()) {
            logger.info(
                    "validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
        }
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        LoginFormsProvider form = context.form();
        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            //TODO missing key challange
            return;
        }
        siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String scriptLink = captchaConfig.getConfig().get(SCRIPT_LINK);
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.addScript(scriptLink);
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - start");
        }
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String secret = captchaConfig.getConfig().get(SITE_SECRET);
            success = validateRecaptcha(context, success, captcha, secret);
        }
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String scriptLink = captchaConfig.getConfig().get(SCRIPT_LINK);
        if (success) {
            super.action(context);
            context.form().addScript(scriptLink);
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(G_RECAPTCHA_RESPONSE);
            Response challengeResponse = challenge(context, Messages.RECAPTCHA_FAILED, "captcha");

            context.form().addScript(scriptLink);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - end");
        }
    }


    protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
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
        logger.warn("Recaptcha success: " + success);
        return success;
    }


}