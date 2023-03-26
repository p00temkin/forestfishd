package crypto.forestfish.forestfishd.api.v1;

public class ForestFishV1Response_knockknock {

	private String version = "v1";
	private String msg = "";

	public ForestFishV1Response_knockknock() {
		super();
	}

	public ForestFishV1Response_knockknock(String _msg) {
		super();
		this.msg = _msg;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}
	
}
