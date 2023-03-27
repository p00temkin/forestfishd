package crypto.forestfish.forestfishd.policy;

import java.util.HashMap;

import crypto.forestfish.enums.evm.EVMChain;

public class Policy {

	@SuppressWarnings("serial")
	private HashMap<String, Boolean> blockchains_enabled = new HashMap<String, Boolean>() {{
		this.put(EVMChain.POLYGON.toString(), true);
		this.put(EVMChain.ETHEREUM.toString(), true);
	}};
	
	// geoip access policy
	@SuppressWarnings("serial")
	private HashMap<String, Boolean> allowedCC = new HashMap<>() {{
		this.put("ALL", true); // no restriction
		
		// Examples
		//this.put("LOCALHOST", true);
		//this.put("RFC1918", true);
		//this.put("US", true);
		
	}};
	
	@SuppressWarnings("serial")
	private HashMap<String, Role> accounts = new HashMap<>() {{
		this.put("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", Role.ADMIN); // https://hardhat.org/hardhat-network/docs/overview Account #0
		this.put("0x12890d2cce102216644c59dae5baed380d84830c", Role.CONSUMER); // https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
	}};

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

	public HashMap<String, Boolean> getAllowedCC() {
		return allowedCC;
	}

	public void setAllowedCC(HashMap<String, Boolean> allowedCC) {
		this.allowedCC = allowedCC;
	}

	public void update() {
		// Make sure we handle all accounts in lowercase
		HashMap<String, Role> accounts_lc = new HashMap<>();
		for (String address: accounts.keySet()) {
			Role r = accounts.get(address);
			accounts_lc.put(address.toLowerCase(), r);
		}
		this.accounts = accounts_lc;
	}
	
}
