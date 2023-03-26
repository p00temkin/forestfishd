package crypto.forestfish.forestfishd.api.v1;

public class ForestFishV1Response_authenticate {

	private String version = "v1";
	private String address = "";
	private boolean success = false;
	private String authmessage = "";
	private String jwtToken = "";

	public ForestFishV1Response_authenticate() {
		super();
	}

	public ForestFishV1Response_authenticate(String _address, boolean _success, String _authmessage, String _jwtToken) {
		super();
		this.address = _address;
		this.success = _success;
		this.authmessage = _authmessage;
		this.jwtToken = _jwtToken;
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

	public String getAuthmessage() {
		return authmessage;
	}

	public void setAuthmessage(String authmessage) {
		this.authmessage = authmessage;
	}
	
}
