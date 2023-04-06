package crypto.forestfish.forestfishd.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.utils.JSONUtils;

public class ConfigUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(ConfigUtils.class);

	public static Policy parsePolicyENV() {
		Policy ffpolicy = null;
		String ffpolicy_env = System.getenv("FFPOLICY");
		if (null == ffpolicy_env) {
			LOGGER.info("FFPOLICY env variable not set");
		} else {
			LOGGER.info("FFPOLICY env variable set, creating policy");
			ffpolicy = JSONUtils.createPOJOFromJSON(ffpolicy_env, Policy.class);
			if (null == ffpolicy) {
				LOGGER.warn("Unable to parse the provided FFPOLICY");
			} else {
				if (null != ffpolicy.getAccounts()) LOGGER.info("Custom policy with " + ffpolicy.getAccounts().size() + " defined accounts");
				if (null != ffpolicy.getBlockchains_enabled()) LOGGER.info("Custom policy with " + ffpolicy.getBlockchains_enabled().size() + " enabled blockchains");
			}
		}
		return ffpolicy;
	}

	public static String parseJWTSecretENV() {
		String secret = null;
		String secret_env = System.getenv("FFSECRET");
		if (null == secret_env) {
			LOGGER.info("FFSECRET env variable not set");
		} else {
			LOGGER.info("FFSECRET env variable set to " + secret_env);
			return secret_env;
		}
		return secret;
	}

}
