package crypto.forestfish.forestfishd;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.forestfishd.singletons.ApiService;
import crypto.forestfish.forestfishd.singletons.ForestFishService;
import crypto.forestfish.forestfishd.utils.ConfigUtils;
import crypto.forestfish.utils.SystemUtils;

public class Start {

	private static final Logger LOGGER = LoggerFactory.getLogger(Start.class);

	public static void main(String[] args) {
		LOGGER.info("init()");
		
		// FFPOLICY
		Policy ffpolicy = ConfigUtils.parsePolicyENV();
		
		// JWT SECRET
		String secret = ConfigUtils.parseJWTSecretENV();
		
		// Initialize settings
		Settings settings = parseCliArgs(args);
		if (null != secret) settings.setJwtSecret(secret);
		settings.sanityCheck();

		// Launch a ForestFishService singleton if needed
		ForestFishService.getInstance(settings, ffpolicy);

		// Launch an ApiService singleton if needed
		ApiService.getInstance(settings.getPort());
	}


	private static Settings parseCliArgs(String[] args) {

		Settings settings = new Settings();
		Options options = new Options();

		// NFT mode
		Option nftMode = new Option("n", "nftmode", false, "NFT Mode, include owned nfts in issued JWT claims");
		nftMode.setRequired(false);
		options.addOption(nftMode);

		// Token mode
		Option tokenMode = new Option("t", "tokenmode", false, "Token Mode, include owned tokens in issued JWT claims");
		tokenMode.setRequired(false);
		options.addOption(tokenMode);

		// API listen port
		Option port = new Option("l", "listenport", true, "REST API port");
		port.setRequired(false);
		options.addOption(port);
		
		// JWT secret
		Option jwtSecret = new Option("s", "jwtsecret", true, "JWT secret (can also be set with FFSECRET env variable)");
		jwtSecret.setRequired(false);
		options.addOption(jwtSecret);

		HelpFormatter formatter = new HelpFormatter();
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd;
		try {
			cmd = parser.parse(options, args);
			if (cmd.hasOption("n")) settings.setNftmode(true);
			if (cmd.hasOption("t")) settings.setTokenmode(true);
			if (cmd.hasOption("l")) settings.setPort(Integer.parseInt(cmd.getOptionValue("listenport")));
			if (cmd.hasOption("s")) settings.setJwtSecret(cmd.getOptionValue("jwtsecret"));
			settings.print();

		} catch (ParseException e) {
			LOGGER.error("ParseException: " + e.getMessage());
			formatter.printHelp(" ", options);
			SystemUtils.halt();
		}

		return settings;
	}

}
