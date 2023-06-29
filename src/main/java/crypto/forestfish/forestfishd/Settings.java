package crypto.forestfish.forestfishd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.utils.SystemUtils;

public class Settings {

	private static final Logger LOGGER = LoggerFactory.getLogger(Settings.class);

	private int port = 6969;
	private String jwtSecret;
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
		if (null != this.getJwtSecret()) System.out.println(" - jwtsecret length: " + this.getJwtSecret().length());
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
			LOGGER.error(" - Invalid port: " + this.getPort());
			SystemUtils.halt();
		}

		// sane JWT secret
		if (null == this.jwtSecret) {
			LOGGER.error(" - The JWT secret needs to be defined");
			SystemUtils.halt();
		}
		if (!(this.jwtSecret.length() >= 50))  {
			LOGGER.error(" - The JWT secret needs to be at least 50 characters, current length is only " + this.jwtSecret.length());
			SystemUtils.halt();
		}

	}

}