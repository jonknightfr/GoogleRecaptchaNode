/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * A node that displays a Google reCAPTCHA widget. 
 */

package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.util.Optional;

import static org.forgerock.openam.auth.node.api.Action.send;

/**
 * A node that increases or decreases the current auth level by a fixed, configurable amount.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
    configClass = RecaptchaNode.Config.class)
public class RecaptchaNode extends SingleOutcomeNode {

    private final static String DEBUG_FILE = "RecaptchaNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/RecaptchaNode";

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The amount to increment/decrement the auth level.
         * @return the amount.
         */
        @Attribute(order = 100)
        String siteKey();
    }

    private final Config config;

    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public RecaptchaNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String script =
            "var recaptchaScript = document.createElement(\"script\");\n" +
            "recaptchaScript.type = \"text/javascript\";\n" +
            "recaptchaScript.src = \"https://www.google.com/recaptcha/api.js\";\n" +
            "document.body.appendChild(recaptchaScript);\n" +
            "\n" +
            "var callbackScript = document.createElement(\"script\");\n" +
            "callbackScript.type = \"text/javascript\";\n" +
            "callbackScript.text = \"function completed() { document.querySelector(\\\"input[type=submit]\\\").click(); }\";\n" +
            "document.body.appendChild(callbackScript);\n" +
            "\n" +
            "submitted = true;\n" +
            "\n" +
            "function callback() {\n" +
            "    document.getElementById(\"loginButton_0\").style.display = \"none\";\n" +
            "\n" +
            "    var div = document.createElement(\"div\");\n" +
            "    div.align = \"center\";\n" +
            "    div.className = \"g-recaptcha\";\n" +
            "    div.setAttribute(\"data-sitekey\", \"" + config.siteKey() + "\");\n" +
            "    div.setAttribute(\"data-callback\" ,\"completed\");\n" +
            "\n" +
            "    var fieldset = document.forms[0].getElementsByTagName(\"fieldset\")[0];\n" +
            "    fieldset.prepend(div);\n" +
            "}\n" +
            "\n" +
            "if (document.readyState !== 'loading') {\n" +
            "  callback();\n" +
            "} else {\n" +
            "  document.addEventListener(\"DOMContentLoaded\", callback);\n" +
            "}";            

        debug.error("[" + DEBUG_FILE + "]: " + "Starting");

        Optional<HiddenValueCallback> result = context.getCallback(HiddenValueCallback.class);
        if (result.isPresent()) {
            return goToNext().build();
        } else {

            String clientSideScriptExecutorFunction = createClientSideScriptExecutorFunction(script, "clientScriptOutputData");
            ScriptTextOutputCallback scriptAndSelfSubmitCallback =
                    new ScriptTextOutputCallback(clientSideScriptExecutorFunction);

            HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("clientScriptOutputData");

            Callback[] callbacks = new Callback[]{scriptAndSelfSubmitCallback, hiddenValueCallback};

            return send(callbacks).build();
        }
    }

    public static String createClientSideScriptExecutorFunction(String script, String outputParameterId) {
        return String.format(
                "(function(output) {\n" +
                "    var autoSubmitDelay = 0,\n" +
                "        submitted = false;\n" +
                "    function submit() {\n" +
                "        if (submitted) {\n" +
                "            return;\n" +
                "        }" +
                "        document.forms[0].submit();\n" +
                "        submitted = true;\n" +
                "    }\n" +
                "    %s\n" + // script
                "    setTimeout(submit, autoSubmitDelay);\n" +
                "}) (document.forms[0].elements['%s']);\n", // outputParameterId
                script,
                outputParameterId);
    }
}
