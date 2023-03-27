package crypto.forestfish.forestfishd.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.forestfishd.policy.Policy;

public class LangUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(LangUtils.class);

	public static String getCCGreeting(String _cc, Policy _policy) {
		if (null != _policy.getAllowedCC().get(_cc)) {
			if ("LOCALHOST".equals(_cc)) return "localhost access _oo_";
			if ("RFC1918".equals(_cc)) return "rfc1918 access _oo_";
			if ("SE".equals(_cc)) return "du har blivit noterad:";
			if ("JP".equals(_cc)) return "あなたは指摘されました:";
			if ("US".equals(_cc)) return "you have been noted:";
		} else {
			if ("US".equals(_cc)) return "turn back";
		}
		return "";
	}
	
}
