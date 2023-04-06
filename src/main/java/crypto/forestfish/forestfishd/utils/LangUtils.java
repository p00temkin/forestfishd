package crypto.forestfish.forestfishd.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.forestfishd.model.policy.Policy;

public class LangUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(LangUtils.class);

	public static String getCCGreeting(String _cc, Policy _policy) {
		if (null != _policy.getAllowedCC().get(_cc)) {
			if ("LOCALHOST".equals(_cc)) return "localhost access _oo_";
			if ("RFC1918".equals(_cc)) return "rfc1918 access _oo_";
			if ("SE".equals(_cc)) return "hejsan.";
			if ("JP".equals(_cc)) return "やあ.";
			if ("US".equals(_cc)) return "hello.";
		} else if (null != _policy.getAllowedCC().get("ALL")) {
			return "all ok.";
		} else {
			return "you be sus.";
		}
		return "";
	}
	
}
