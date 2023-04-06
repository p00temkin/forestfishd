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
		assertEquals("Ensure default config", "{\"accounts\":{\"0x12890d2cce102216644c59dae5baed380d84830c\":\"CONSUMER\",\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\":\"ADMIN\"},\"allowedCC\":{\"ALL\":true},\"blockchains_enabled\":{\"POLYGON\":true,\"ETHEREUM\":true}}", json);
	}

}
