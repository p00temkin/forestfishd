package crypto.forestfish.forestfishd.policy;

import java.util.HashMap;

import crypto.forestfish.enums.evm.EVMChain;

public class Policy {

	@SuppressWarnings("serial")
	private HashMap<String, Boolean> blockchains_enabled = new HashMap<String, Boolean>() {{
		this.put(EVMChain.POLYGON.toString(), true);
		this.put(EVMChain.ETHEREUM.toString(), true);
	}};
	
	private HashMap<String, Role> accounts;

	public Policy() {
		super();
	}

	public HashMap<String, Boolean> getBlockchains_enabled() {
		return blockchains_enabled;
	}

	public void setBlockchains_enabled(HashMap<String, Boolean> blockchains_enabled) {
		this.blockchains_enabled = blockchains_enabled;
	}

	public HashMap<String, Role> getAccounts() {
		return accounts;
	}

	public void setAccounts(HashMap<String, Role> accounts) {
		this.accounts = accounts;
	}
	
}
