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

import crypto.forestfish.forestfishd.singletons.ApiService;
import crypto.forestfish.forestfishd.singletons.ForestFishService;
import crypto.forestfish.utils.SystemUtils;

public class Start {

	private static final Logger LOGGER = LoggerFactory.getLogger(Start.class);

	public static void main(String[] args) {
		LOGGER.info("init()");

		// Initialize settings
		Settings settings = parseCliArgs(args);
		settings.sanityCheck();

		// Launch a ForestFishService singleton if needed
		ForestFishService.getInstance(settings);

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

		HelpFormatter formatter = new HelpFormatter();
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd;
		try {
			cmd = parser.parse(options, args);
			if (cmd.hasOption("n")) settings.setNftmode(true);
			if (cmd.hasOption("t")) settings.setTokenmode(true);
			if (cmd.hasOption("l")) settings.setPort(Integer.parseInt(cmd.getOptionValue("listenport")));
			settings.print();

		} catch (ParseException e) {
			LOGGER.error("ParseException: " + e.getMessage());
			formatter.printHelp(" ", options);
			SystemUtils.halt();
		}

		return settings;
	}

}
