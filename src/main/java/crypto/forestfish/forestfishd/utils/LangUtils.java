package crypto.forestfish.forestfishd.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.forestfishd.policy.Policy;

public class LangUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(LangUtils.class);

	public static String getCCGreeting(String _cc, Policy _policy) {
		if (null != _policy.getAllowedCC().get(_cc)) {
			if ("SE".equals(_cc)) return "hej";
			if ("JP".equals(_cc)) return "こんにちは";
			if ("US".equals(_cc)) return "hello";
		} else {
			if ("US".equals(_cc)) return "turn back";
		}
		return "";
	}
	
}
