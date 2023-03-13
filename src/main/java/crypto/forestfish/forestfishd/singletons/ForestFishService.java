package crypto.forestfish.forestfishd.singletons;

import java.io.File;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.CryptoUtils;

import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader.FileMode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.Country;

import crypto.forestfish.forestfishd.Settings;
import crypto.forestfish.forestfishd.policy.Policy;
import crypto.forestfish.objects.evm.connector.EVMBlockChainUltraConnector;
import crypto.forestfish.utils.CryptUtils;
import crypto.forestfish.utils.FilesUtils;
import crypto.forestfish.utils.SystemUtils;
import crypto.forestfish.enums.BlockchainType;
import crypto.forestfish.enums.evm.EVMChain;

public class ForestFishService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ForestFishService.class);
	private static ForestFishService single_instance = null;	

	private static Settings settings;

	// wallet address, challenge
	private static HashMap<String, String> challenges = new HashMap<>();

	// JWT secret
	private static String secret;

	// Blockchain connectors
	private static EVMBlockChainUltraConnector ultra_connector;

	// Support
	private static DatabaseReader geo2CityService;
	private int geoIPcacheSize = 8096;
	
	// Policy
	private static Policy policy;

	public ForestFishService() {
		super();
	}

	@SuppressWarnings("serial")
	public ForestFishService(Settings s) {
		super();
		settings = s;
		
		LOGGER.info("Launching ForestFishService");

		/**
		 * Generate/get secret unless exists
		 */
		File f = new File("secret");
		if (!f.exists()) {
			secret = CryptUtils.generateRandomString();
			FilesUtils.writeToFileUNIXNoException(secret, "secret");
		} else {
			String temp_secret = FilesUtils.readAllFromFile(f);
			if ((null != temp_secret) && (temp_secret.length() == 54)) {
				secret = temp_secret;
			} else {
				LOGGER.error("Found invalid secret file content of length " + temp_secret.length() + ": " + temp_secret);
				SystemUtils.halt();
			}
		}
		LOGGER.info("Moving forward with secret: " + secret);
		
		/**
		 * Blockchain support
		 */
		if (s.isNftmode() || s.isTokenmode()) {
			ultra_connector = new EVMBlockChainUltraConnector(BlockchainType.PUBLIC,
					new HashMap<String, Boolean>() {{
						this.put(EVMChain.POLYGON.toString(), true);
						this.put(EVMChain.ETHEREUM.toString(), true);
					}});
		}

		/*
		 * GeoIP2 City
		 */
		String geo2CityPath = "etc/forestfish/geoip/GeoLite2-City.mmdb";
		File geo2CityFile = new File(geo2CityPath);
		if (!geo2CityFile.exists()) {
			LOGGER.error("Unable to find GeoIP2 file: " + geo2CityPath);
			SystemUtils.halt();
		}
		try {
			geo2CityService = new DatabaseReader
					.Builder(geo2CityFile)
					.fileMode(FileMode.MEMORY)
					.withCache(new CHMCache(geoIPcacheSize))
					.build();
			LOGGER.info("GeoLite2-City.mmdb version: " + geo2CityService.getMetadata().getBuildDate());
		} catch (Exception e) {
			LOGGER.error("Unable to launch geoIP2 City service");
			SystemUtils.halt();
		}
		
		/**
		 * Policy
		 */
		policy = new Policy();
		
	}

	public static ForestFishService getInstance(Settings _settings, Policy _ffpolicy) {
		if (null != _ffpolicy) policy = _ffpolicy;
		if (single_instance == null) single_instance = new ForestFishService(_settings);
		return single_instance;
	}

	public static String getChallengeForWallet(String address) {
		String challenge = challenges.get(address);
		// generate a new challenge if missing
		if (null == challenge) {
			challenge = generateRandomStringUUID();
			challenges.put(address, challenge);
		}
		return challenge;
	}

	public static String generateRandomStringUUID() {
		return UUID.randomUUID().toString();
	}

	public static void generateNewChallengeForWallet(String address) {
		String challenge = generateRandomStringUUID();
		challenges.put(address, challenge);
	}

	public static String getSecret() {
		return secret;
	}

	public static void setSecret(String secret) {
		ForestFishService.secret = secret;
	}

	public static EVMBlockChainUltraConnector getUltra_connector() {
		return ultra_connector;
	}

	public static void setUltra_connector(EVMBlockChainUltraConnector ultra_connector) {
		ForestFishService.ultra_connector = ultra_connector;
	}

	public static Settings getSettings() {
		return settings;
	}

	public static void setSettings(Settings settings) {
		ForestFishService.settings = settings;
	}

	public static String lookupCountryCodeForIP(InetAddress ipAddress) {
		try {
			CityResponse response = geo2CityService.city(ipAddress);
			Country country = response.getCountry();
			if (country.getIsoCode() == null) {
				return "N/A";
			}
			return country.getIsoCode();
		} catch (Exception e) {
			return "N/A";
		}
	}

	public static String lookupCountryCodeForIP(final String ip) {
		try {
			InetAddress ipAddress = InetAddress.getByName(ip);
			return lookupCountryCodeForIP(ipAddress);
		} catch (Exception e) {
			return "N/A";
		}
	}

	public static Policy getPolicy() {
		return policy;
	}

	public static void setPolicy(Policy policy) {
		ForestFishService.policy = policy;
	}

}
