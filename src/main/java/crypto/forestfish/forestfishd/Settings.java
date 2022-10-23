package crypto.forestfish.forestfishd;

import crypto.forestfish.utils.SystemUtils;

public class Settings {

	private int port = 6969;
	private String jwtSecret = "secret";
	private boolean nftmode = false;
	private boolean tokenmode = false;

	public Settings() {
		super();
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}
	
	public String getJwtSecret() {
		return jwtSecret;
	}

	public void setJwtSecret(String jwtSecret) {
		this.jwtSecret = jwtSecret;
	}

	public boolean isNftmode() {
		return nftmode;
	}

	public void setNftmode(boolean nftmode) {
		this.nftmode = nftmode;
	}

	public void print() {
        System.out.println("Settings:");
        System.out.println(" - port: " + this.getPort());
        System.out.println(" - jwtsecret length: " + this.getJwtSecret().length());
        System.out.println(" - nftmode: " + this.isNftmode());
        System.out.println(" - tokenmode: " + this.isTokenmode());
    }
	
    public boolean isTokenmode() {
		return tokenmode;
	}

	public void setTokenmode(boolean tokenmode) {
		this.tokenmode = tokenmode;
	}

	public void sanityCheck() {
    	
    	// sane port
    	if ((this.port > 0) && (this.port <= 65535))  {
    		// ok
    	} else {
            System.out.println(" - Invalid port: " + this.getPort());
            SystemUtils.halt();
        }

    }
}
