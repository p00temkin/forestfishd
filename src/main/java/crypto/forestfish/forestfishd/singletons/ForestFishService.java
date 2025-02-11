package crypto.forestfish.forestfishd.singletons;

import java.io.File;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader.FileMode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.Country;

import crypto.forestfish.forestfishd.Settings;
import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.objects.evm.connector.EVMBlockChainUltraConnector;
import crypto.forestfish.utils.CryptUtils;
import crypto.forestfish.utils.FilesUtils;
import crypto.forestfish.utils.JSONUtils;
import crypto.forestfish.utils.NetUtils;
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
	private static boolean allow_policy_reconfig_over_rest = false;
	private static boolean allow_policy_reconfig_over_rest_from_rfc1918 = false;

	public ForestFishService() {
		super();
	}

	@SuppressWarnings("serial")
	private ForestFishService(Settings _settings) {
		super();
		settings = _settings;

		LOGGER.info("Launching ForestFishService with default policy");

		/**
		 * Generate/get secret unless exists
		 */
		if (null == _settings.getJwtSecret()) {
			File f = new File("secret");
			if (!f.exists()) {
				LOGGER.info("No secret specified (missing cli -s option, FFSECRET env variable, cached secret file), so generating one");
				secret = CryptUtils.generateRandomString();
			} else {
				LOGGER.info("No secret specified (missing cli -s option, FFSECRET env variable), but found cached secret file");
				String temp_secret = FilesUtils.readAllFromFile(f);
				if ((null != temp_secret) && (temp_secret.length() == 54)) {
					secret = temp_secret;
				} else {
					LOGGER.error("Found invalid secret file content of length " + temp_secret.length() + ": " + temp_secret);
					SystemUtils.halt();
				}
			}
		} else {
			secret = _settings.getJwtSecret();
		}
		LOGGER.info("Moving forward with secret: " + secret);

		// Always flush JWT secret
		FilesUtils.writeToFileUNIXNoException(secret, "secret");
		LOGGER.info("Flushed JWT secret to local file");

		/**
		 * Blockchain support
		 */
		if (_settings.isNftmode() || _settings.isTokenmode()) {
			ultra_connector = new EVMBlockChainUltraConnector(BlockchainType.PUBLIC,
					new HashMap<String, Boolean>() {{
						this.put(EVMChain.POLYGON.toString(), true);
						this.put(EVMChain.ETH.toString(), true);
					}},
					ForestFishService.getSettings().isHalt_on_rpc_errors());
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

		// Transfer REST policy reconfig setting 
		allow_policy_reconfig_over_rest = settings.isAllow_policy_reconfig_over_rest();
		allow_policy_reconfig_over_rest_from_rfc1918 = settings.isAllow_policy_reconfig_over_rest_from_rfc1918();

	}

	public static ForestFishService getInstance(Settings _settings, Policy _ffpolicy) {

		// First check for stored policy copy
		File f = new File("ffpolicy.json");
		if (f.exists()) {
			String json = FilesUtils.readAllFromFile(f);
			Policy ffpolicy_temp = JSONUtils.createPOJOFromJSON(json, Policy.class);
			if (null != ffpolicy_temp) policy = ffpolicy_temp;
		}

		// Check for ENV supplied policy
		if (null == policy) {
			if (null != _ffpolicy) {
				LOGGER.info("Launching with custom Policy");
				policy = _ffpolicy;
				
				String json = JSONUtils.createJSONFromPOJO(policy);
				FilesUtils.writeToFileUNIXNoException(json, "ffpolicy.json");
			} else {
				LOGGER.info("Launching with default Policy");
				policy = new Policy();
			}
		}
		
		policy.update();
		
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

	public static String lookupCountryCodeForIP(final String _ip) {
		try {
			if (NetUtils.isValidIPV4(_ip)) {
				if (NetUtils.isRFC1918(_ip)) {
					return "RFC1918";
				}
				if (NetUtils.isLocalHost(_ip)) {
					return "LOCALHOST";
				}
				InetAddress ipAddress = InetAddress.getByName(_ip);
				return lookupCountryCodeForIP(ipAddress);
			}
			return "N/A";
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

	public static boolean isAllow_policy_reconfig_over_rest() {
		return allow_policy_reconfig_over_rest;
	}

	public static void setAllow_policy_reconfig_over_rest(boolean allow_policy_reconfig_over_rest) {
		ForestFishService.allow_policy_reconfig_over_rest = allow_policy_reconfig_over_rest;
	}

	public static boolean isAllow_policy_reconfig_over_rest_from_rfc1918() {
		return allow_policy_reconfig_over_rest_from_rfc1918;
	}

	public static void setAllow_policy_reconfig_over_rest_from_rfc1918(
			boolean allow_policy_reconfig_over_rest_from_rfc1918) {
		ForestFishService.allow_policy_reconfig_over_rest_from_rfc1918 = allow_policy_reconfig_over_rest_from_rfc1918;
	}

}
