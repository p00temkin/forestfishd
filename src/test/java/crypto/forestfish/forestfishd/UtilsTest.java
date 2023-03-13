package crypto.forestfish.forestfishd;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import crypto.forestfish.forestfishd.policy.Policy;
import crypto.forestfish.utils.JSONUtils;

public class UtilsTest {

	@Test
	public void testPolicyJSONFlush() {
		Policy p = new Policy();
		String json = JSONUtils.createJSONFromPOJO(p);
		System.out.println(json);
		assertEquals("Ensure default config", "{\"accounts\":{\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\":\"ADMIN\"},\"allowedCC\":{\"SE\":true,\"JP\":true,\"US\":true},\"blockchains_enabled\":{\"POLYGON\":true,\"ETHEREUM\":true}}", json);
	}

}
