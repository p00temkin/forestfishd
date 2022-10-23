package crypto.forestfish.forestfishd.api.v1;

public class ForestFishV1Response_authenticate {

	private String version = "v1";
	private String address = "";
	private boolean valid = false;
	private boolean success = false;
	private String jwtToken = "";

	public ForestFishV1Response_authenticate() {
		super();
	}

	public ForestFishV1Response_authenticate(String address, boolean valid, boolean success, String jwtToken) {
		super();
		this.address = address;
		this.valid = valid;
		this.success = success;
		this.jwtToken = jwtToken;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public String getJwtToken() {
		return jwtToken;
	}

	public void setJwtToken(String jwtToken) {
		this.jwtToken = jwtToken;
	}
	
}
