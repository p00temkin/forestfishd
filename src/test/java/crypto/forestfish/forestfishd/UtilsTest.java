package crypto.forestfish.forestfishd;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.utils.JSONUtils;

public class UtilsTest {

	@Test
	public void testPolicyJSONFlush() {
		Policy p = new Policy();
		String json = JSONUtils.createJSONFromPOJO(p);
		System.out.println(json);
		assertEquals("Ensure default config", "{\"accounts\":{},\"allowedCC\":{\"ALL\":true},\"blockchains_enabled\":{\"POLYGON\":true,\"ETH\":true}}", json);
	}

}
