package crypto.forestfish.forestfishd.api;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import crypto.forestfish.enums.evm.EVMChain;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_knockknock;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_challenge;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_knockknock;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_protectedcontent;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_status;
import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.forestfishd.model.policy.Role;
import crypto.forestfish.forestfishd.singletons.ForestFishService;
import crypto.forestfish.forestfishd.utils.LangUtils;
import crypto.forestfish.objects.evm.EVMAccountBalance;
import crypto.forestfish.objects.evm.EVMNftAccountBalance;
import crypto.forestfish.objects.evm.EVMPortfolio;
import crypto.forestfish.objects.evm.connector.EVMBlockChainUltraConnector;
import crypto.forestfish.objects.jwt.JWTSignedDecodeResult;
import crypto.forestfish.objects.jwt.TokenType;
import crypto.forestfish.utils.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Path("/api/forestfish/")
@Produces(MediaType.APPLICATION_JSON)
public class ForestFishV1RestService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ForestFishV1RestService.class);

	// curl -s -X GET "localhost:6969/api/forestfish/v1/status"
	@GET
	@Path("/v1/status")
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_status() {
		LOGGER.info("v1_status()");

		ForestFishV1Response_status pb = new ForestFishV1Response_status("up");
		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.entity(JSONUtils.createJSONFromPOJO(pb))
				.build();

	}

	// curl -s -X POST "localhost:6969/api/forestfish/v1/knockknock" -H 'Content-Type: application/json' -d '{"version":"v1","address":"0x12890d2cce102216644c59dae5baed380d84830c"}'
	@POST
	@Path("/v1/knockknock")
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_knockknock(@HeaderParam("X-Real-IP") String xrealIP, @Context HttpServletRequest request, String reqSTR) {
		LOGGER.info("v1_knockknock()");

		ForestFishV1Request_knockknock req = JSONUtils.createPOJOFromJSON(reqSTR, ForestFishV1Request_knockknock.class);
		String delimiterchar = ";";

		if (null != req) {
			String msg = "";
			String remoteIP = request.getRemoteAddr();
			if ("[0:0:0:0:0:0:0:1]".equals(remoteIP)) remoteIP = "127.0.0.1";

			if (null != xrealIP) {
				if (NetUtils.isValidIPV4(xrealIP)) {
					remoteIP = xrealIP;
				}
			}

			if (NetUtils.isValidIPV4(remoteIP)) {
				String cc = ForestFishService.lookupCountryCodeForIP(remoteIP);
				LOGGER.info("cc " + cc + " for " + remoteIP);
				msg = LangUtils.getCCGreeting(cc, ForestFishService.getPolicy());

				String address = req.getAddress();
				if (null != address) {
					address = address.toLowerCase();
					if (EVMUtils.isValidEthereumAddress(address)) {
						msg = msg + delimiterchar + address + delimiterchar + remoteIP; 
						LOGGER.info("v1_knockknock() called with valid address " + address);
					} else {
						LOGGER.warn("v1_knockknock() called with invalid address " + address);
						msg = msg + delimiterchar + remoteIP; 
					}
				} else {
					msg = msg + delimiterchar + remoteIP;
				}

				boolean preregistered = false;
				Policy pol = ForestFishService.getPolicy();
				Role role = null;
				if (null != pol) {
					if (null != pol.getAccounts()) {
						role = pol.getAccounts().get(req.getAddress().toLowerCase());
						if (null != role) {
							preregistered = true;
						}
					}
				}

				LOGGER.info("Replying to a knock from " + remoteIP + ": " + msg);
				if (role == null) role = Role.UNDEFINED;
				ForestFishV1Response_knockknock kk = new ForestFishV1Response_knockknock(req.getAddress(), remoteIP, cc, msg, preregistered, role.toString());

				return Response
						.status(200)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
						.header("Access-Control-Max-Age", "1209600")
						.entity(JSONUtils.createJSONFromPOJO(kk))
						.build();

			} else {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Access Denied, invalid IP")
						.build();
			}

		} else {
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}
	}

	// CORS, https://localcoder.org/how-to-enable-cross-domain-requests-on-jax-rs-web-services
	// curl -s -X OPTIONS "localhost:6969/api/forestfish/v1/knockknock" 
	@OPTIONS
	@Path("/v1/knockknock")
	public Response knockknock_options() {
		LOGGER.info("OPTIONS req for /v1/knockknock");

		return Response.ok("")
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.build();
	}

	// curl -s -X GET "localhost:6969/api/forestfish/v1/getchallenge/0x12890D2cce102216644c59daE5baed380d84830c" 
	@GET
	@Path("/v1/getchallenge/{address}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_getchallenge(@PathParam("address") String address) {
		LOGGER.info("v1_getchallenge()");

		address = address.toLowerCase();
		String challenge = "";
		boolean valid = false;
		if (EVMUtils.isValidEthereumAddress(address)) {
			LOGGER.info("v1_getchallenge() called with valid address " + address);
			challenge = ForestFishService.getChallengeForWallet(address);
			valid = true;
		} else {
			LOGGER.warn("v1_getchallenge() called with invalid address " + address);
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}
		ForestFishV1Response_challenge pb = new ForestFishV1Response_challenge(address, challenge, valid);

		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.entity(JSONUtils.createJSONFromPOJO(pb))
				.build();
	}

	// curl -s -X GET "localhost:6969/api/forestfish/v1/ping"
	@GET
	@Path("v1/ping")
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_ping() {
		LOGGER.info("v1_ping()");

		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST")
				.header("Access-Control-Max-Age", "1209600")
				.entity("{\"version\":\"v1\",\"pong\":true}")
				.build();
	}
	
	// curl -s -X POST "localhost:6969/api/forestfish/v1/authz" -H 'Content-Type: application/json' -d '{"version":"v1","challenge":"a2278ea3-4459-4ecd-8f05-b53c12ac0597","address":"0x12890d2cce102216644c59dae5baed380d84830c","signature":"0x16672d6205b5557e834a4c9e81e07475d396a13c6c7ef10c959133da4efdac200x1c7918ae6e3a308838b6a923874ff0ba1524c95f6a8db9a257f5264c1858834b1c"}'
	@POST
	@Path("/v1/authn")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_authn(@HeaderParam("X-Real-IP") String xrealIP, @Context HttpServletRequest request, String reqSTR) {
		LOGGER.info("v1_authn()");
		TokenType tokentype = TokenType.AUTHN;

		ForestFishV1Request_authenticate req = JSONUtils.createPOJOFromJSON(reqSTR, ForestFishV1Request_authenticate.class);
		String authmessage = "";
		int authcode = 404;
		boolean success = false;
		String jwtToken = "";
		String address = "";
		if (null != req) {
			String remoteIP = request.getRemoteAddr();
			if ("[0:0:0:0:0:0:0:1]".equals(remoteIP)) remoteIP = "127.0.0.1";

			if (null != xrealIP) {
				if (NetUtils.isValidIPV4(xrealIP)) {
					remoteIP = xrealIP;
				}
			}

			if (NetUtils.isValidIPV4(remoteIP)) {
				String cc = ForestFishService.lookupCountryCodeForIP(remoteIP);
				LOGGER.info("v1_authn() called with address=" + req.getAddress() + ", challenge=" + req.getChallenge() + ", signature=" + req.getSignature() + ", cc=" + cc);
				if (EVMUtils.isValidEthereumAddress(req.getAddress().toLowerCase())) {
					address = req.getAddress().toLowerCase();
					String storedChallenge = ForestFishService.getChallengeForWallet(address);
					if (!storedChallenge.equals(req.getChallenge())) {
						LOGGER.warn("Attempt to replay old challenge " + req.getChallenge() + ", current challenge is " + storedChallenge);
						authmessage = "Attempt to replay old challenge " + req.getChallenge() + ", current challenge is " + storedChallenge;
						authcode = 401;
						success = false;
					} else {
						success = EVMUtils.verify(req.getSignature(), req.getChallenge(), address);
						if (success) {

							// Successful signature, dont verify policy
							LOGGER.info("Successful authentication for wallet " + address + ", AUTHN so no policy check, creating new challenge");
							authmessage = "Successful authentication for wallet " + address + ", AUTHN so no policy check, creating new challenge";
							authcode = 200;
							ForestFishService.generateNewChallengeForWallet(address);

							LOGGER.info("Creating JWT token for wallet " + address);
							String jwt_secret = ForestFishService.getSecret();
							Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwt_secret), 
									SignatureAlgorithm.HS256.getJcaName());
							Instant now = Instant.now();

							Map<String, Object> private_claims = new HashMap<>();
							private_claims.put("evm_wallet_address", address);
							private_claims.put("token_type", tokentype.toString());

							if (ForestFishService.getSettings().isNftmode() || ForestFishService.getSettings().isTokenmode()) {
								EVMBlockChainUltraConnector ultra_connector = ForestFishService.getUltra_connector();
								if (null == ultra_connector) {
									LOGGER.error("ultra_connector is null ..");
								} else {
									EVMPortfolio portfolio = EVMUtils.getEVMPortfolioForAccount(ultra_connector, address, ForestFishService.getSettings().isHalt_on_rpc_errors());

									// NFT check
									if (null != portfolio) {
										if (null != portfolio.getChainportfolio()) {
											if (ForestFishService.getSettings().isNftmode()) {
												if (null != portfolio.getChainportfolio().get(EVMChain.POLYGON)) {
													if (!portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().isEmpty()) {
														for (String nftName: portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().keySet()) {
															EVMNftAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().get(nftName);
															System.out.println("POLYGON NFT ownership: " + nftName + " bal: " + bal.getBalance());
															private_claims.put("nft_ownership:" + EVMChain.POLYGON.toString() + ":" + nftName, bal.getBalance());
														}
													}
												}

												if (null != portfolio.getChainportfolio().get(EVMChain.ETH)) {
													if (!portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().isEmpty()) {
														for (String nftName: portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().keySet()) {
															EVMNftAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().get(nftName);
															System.out.println("ETHEREUM NFT ownership: " + nftName + " bal: " + bal.getBalance());
															private_claims.put("nft_ownership:" + EVMChain.ETH.toString() + ":" + nftName, bal.getBalance());
														}
													}
												}
											}

											// ERC-20 check
											if (ForestFishService.getSettings().isTokenmode()) {
												if (null != portfolio.getChainportfolio().get(EVMChain.POLYGON)) {
													if (!portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().isEmpty()) {
														for (String tokenName: portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().keySet()) {
															EVMAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().get(tokenName);
															System.out.println("POLYGON ERC20 ownership: " + tokenName + " bal: " + bal.getBalanceInWEI());
															private_claims.put("erc20_ownership:" + EVMChain.POLYGON.toString() + ":" + tokenName, bal.getBalanceInWEI());
														}
													}
												}

												if (null != portfolio.getChainportfolio().get(EVMChain.ETH)) {
													if (!portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().isEmpty()) {
														for (String tokenName: portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().keySet()) {
															EVMAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().get(tokenName);
															System.out.println("ETHEREUM ERC20 ownership: " + tokenName + " bal: " + bal.getBalanceInWEI());
															private_claims.put("erc20_ownership:" + EVMChain.ETH.toString() + ":" + tokenName, bal.getBalanceInWEI());
														}
													}
												}
											}
										}
									}
								}
							}

							jwtToken = Jwts.builder()

									// private claims
									//.claim("evm_wallet_address", address) // private claim
									.addClaims(private_claims)

									// registered claims
									.setIssuer("forestfishd") // move to conf
									.setAudience("web3did") // move to conf
									.setSubject(address) // sub, user identifier
									.setIssuedAt(Date.from(now)) // iat
									.setExpiration(Date.from(now.plus(1, ChronoUnit.DAYS))) // exp, 1 days
									.setId(UUID.randomUUID().toString()) // jti, unique JWT token identifier

									// signature
									.signWith(hmacKey)
									.setHeaderParam("typ","JWT")

									// finalize
									.compact();

							LOGGER.info("Created JWT token for wallet " + address + ", token: " + jwtToken);

						} else {
							LOGGER.warn("Unsuccessful authentication attempt for wallet " + address);
							authmessage = "Unsuccessful authentication attempt for wallet " + address;
							authcode = 405;
							success = false;
						}
					}
				} else {
					LOGGER.info("v1_authn() called with invalid address=" + req.getAddress());
					return Response
							.status(403)
							.header("Access-Control-Allow-Origin", "*")
							.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
							.header("Access-Control-Allow-Credentials", "true")
							.header("Access-Control-Allow-Methods", "GET, POST")
							.header("Access-Control-Max-Age", "1209600")
							.entity("Access Denied, invalid address specified")
							.build();
				}

			} else {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Access Denied, invalid IP")
						.build();
			}

		} else {
			LOGGER.warn("Invalid POST request noted: " + reqSTR);
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}
		ForestFishV1Response_authenticate pb = new ForestFishV1Response_authenticate(address, success, authcode, authmessage, jwtToken);
		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				.header("Access-Control-Max-Age", "1209600")
				.entity(JSONUtils.createJSONFromPOJO(pb))
				.build();
	}

	// curl -s -X POST "localhost:6969/api/forestfish/v1/authz" -H 'Content-Type: application/json' -d '{"version":"v1","challenge":"a2278ea3-4459-4ecd-8f05-b53c12ac0597","address":"0x12890d2cce102216644c59dae5baed380d84830c","signature":"0x16672d6205b5557e834a4c9e81e07475d396a13c6c7ef10c959133da4efdac200x1c7918ae6e3a308838b6a923874ff0ba1524c95f6a8db9a257f5264c1858834b1c"}'
	@POST
	@Path("/v1/authz")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_authz(@HeaderParam("X-Real-IP") String xrealIP, @Context HttpServletRequest request, String reqSTR) {
		LOGGER.info("v1_authz()");
		TokenType tokentype = TokenType.AUTHZ;

		ForestFishV1Request_authenticate req = JSONUtils.createPOJOFromJSON(reqSTR, ForestFishV1Request_authenticate.class);
		String authmessage = "";
		int authcode = 404;
		boolean success = false;
		String jwtToken = "";
		String address = "";
		if (null != req) {
			String remoteIP = request.getRemoteAddr();
			if ("[0:0:0:0:0:0:0:1]".equals(remoteIP)) remoteIP = "127.0.0.1";

			if (null != xrealIP) {
				if (NetUtils.isValidIPV4(xrealIP)) {
					remoteIP = xrealIP;
				}
			}

			if (NetUtils.isValidIPV4(remoteIP)) {
				String cc = ForestFishService.lookupCountryCodeForIP(remoteIP);
				LOGGER.info("v1_authz() called with address=" + req.getAddress() + ", challenge=" + req.getChallenge() + ", signature=" + req.getSignature() + ", cc=" + cc);
				if (EVMUtils.isValidEthereumAddress(req.getAddress().toLowerCase())) {
					address = req.getAddress().toLowerCase();
					String storedChallenge = ForestFishService.getChallengeForWallet(address);
					if (!storedChallenge.equals(req.getChallenge())) {
						LOGGER.warn("Attempt to replay old challenge " + req.getChallenge() + ", current challenge is " + storedChallenge);
						authmessage = "Attempt to replay old challenge " + req.getChallenge() + ", current challenge is " + storedChallenge;
						authcode = 401;
						success = false;
					} else {
						success = EVMUtils.verify(req.getSignature(), req.getChallenge(), address);
						if (success) {

							// Successful signature, verify policy
							boolean cc_policy_allows_access = false;
							boolean account_policy_allows_access = true;
							Policy pol = ForestFishService.getPolicy();
							Role role = null;
							if ((null != pol) && (null != pol.getAllowedCC())) {
								LOGGER.info("allowed ccs: " + pol.getAllowedCC().keySet());

								// Check if there is a cc restriction
								if (null != pol.getAllowedCC().get("ALL")) {
									cc_policy_allows_access = true;
								} else {
									if (null != pol.getAllowedCC().get(cc)) {
										cc_policy_allows_access = true;
									}
								}
								if (!cc_policy_allows_access) {
									LOGGER.warn("Successful authentication for wallet " + address + " but denied by cc policy");
									authmessage = "Successful authentication for wallet " + address + " but denied by cc policy";
									authcode = 402;
									success = false;
								}

								// Check for address restriction
								if (null == pol.getAccounts()) {
									LOGGER.warn("No accounts are setup, will deny all requests");
									account_policy_allows_access = false;
								} else {
									role = pol.getAccounts().get(req.getAddress().toLowerCase());
									if (null != role) {
										account_policy_allows_access = true;
										LOGGER.info("Found approved account " + req.getAddress() + " with role " + role);
									} else {
										LOGGER.info("Account " + req.getAddress() + " not approved");
										account_policy_allows_access = false;
									}
								}
								if (!account_policy_allows_access) {
									LOGGER.warn("Successful authentication for wallet " + address + " but denied by account policy");
									authmessage = "Successful authentication for wallet " + address + " but denied by account policy";
									authcode = 403;
									success = false;
								}

							} else {
								LOGGER.warn("Successful authentication for wallet " + address + " but invalid policy");
								authmessage = "Successful authentication for wallet " + address + " but invalid policy";
								authcode = 404;
								success = false;
							}

							if (cc_policy_allows_access && account_policy_allows_access) {
								LOGGER.info("Successful authentication for wallet " + address + ", access allowed by policy, creating new challenge");
								authmessage = "Successful authentication for wallet " + address + ", access allowed by policy, creating new challenge";
								authcode = 200;
								ForestFishService.generateNewChallengeForWallet(address);

								LOGGER.info("Creating JWT token for wallet " + address);
								String jwt_secret = ForestFishService.getSecret();
								Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwt_secret), 
										SignatureAlgorithm.HS256.getJcaName());
								Instant now = Instant.now();

								Map<String, Object> private_claims = new HashMap<>();
								private_claims.put("evm_wallet_address", address);
								private_claims.put("token_type", tokentype.toString());
								private_claims.put("role", role.toString());

								if (ForestFishService.getSettings().isNftmode() || ForestFishService.getSettings().isTokenmode()) {
									EVMBlockChainUltraConnector ultra_connector = ForestFishService.getUltra_connector();
									if (null == ultra_connector) {
										LOGGER.error("ultra_connector is null ..");
									} else {
										EVMPortfolio portfolio = EVMUtils.getEVMPortfolioForAccount(ultra_connector, address, ForestFishService.getSettings().isHalt_on_rpc_errors());

										// NFT check
										if (null != portfolio) {
											if (null != portfolio.getChainportfolio()) {
												if (ForestFishService.getSettings().isNftmode()) {
													if (null != portfolio.getChainportfolio().get(EVMChain.POLYGON)) {
														if (!portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().isEmpty()) {
															for (String nftName: portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().keySet()) {
																EVMNftAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc721tokens().get(nftName);
																System.out.println("POLYGON NFT ownership: " + nftName + " bal: " + bal.getBalance());
																private_claims.put("nft_ownership:" + EVMChain.POLYGON.toString() + ":" + nftName, bal.getBalance());
															}
														}
													}

													if (null != portfolio.getChainportfolio().get(EVMChain.ETH)) {
														if (!portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().isEmpty()) {
															for (String nftName: portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().keySet()) {
																EVMNftAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.ETH).getErc721tokens().get(nftName);
																System.out.println("ETHEREUM NFT ownership: " + nftName + " bal: " + bal.getBalance());
																private_claims.put("nft_ownership:" + EVMChain.ETH.toString() + ":" + nftName, bal.getBalance());
															}
														}
													}
												}

												// ERC-20 check
												if (ForestFishService.getSettings().isTokenmode()) {
													if (null != portfolio.getChainportfolio().get(EVMChain.POLYGON)) {
														if (!portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().isEmpty()) {
															for (String tokenName: portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().keySet()) {
																EVMAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.POLYGON).getErc20tokens().get(tokenName);
																System.out.println("POLYGON ERC20 ownership: " + tokenName + " bal: " + bal.getBalanceInWEI());
																private_claims.put("erc20_ownership:" + EVMChain.POLYGON.toString() + ":" + tokenName, bal.getBalanceInWEI());
															}
														}
													}

													if (null != portfolio.getChainportfolio().get(EVMChain.ETH)) {
														if (!portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().isEmpty()) {
															for (String tokenName: portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().keySet()) {
																EVMAccountBalance bal = portfolio.getChainportfolio().get(EVMChain.ETH).getErc20tokens().get(tokenName);
																System.out.println("ETHEREUM ERC20 ownership: " + tokenName + " bal: " + bal.getBalanceInWEI());
																private_claims.put("erc20_ownership:" + EVMChain.ETH.toString() + ":" + tokenName, bal.getBalanceInWEI());
															}
														}
													}
												}
											}
										}
									}
								}

								jwtToken = Jwts.builder()

										// private claims
										//.claim("evm_wallet_address", address) // private claim
										.addClaims(private_claims)

										// registered claims
										.setIssuer("forestfishd") // move to conf
										.setAudience("web3did") // move to conf
										.setSubject(address) // sub, user identifier
										.setIssuedAt(Date.from(now)) // iat
										.setExpiration(Date.from(now.plus(1, ChronoUnit.DAYS))) // exp, 1 days
										.setId(UUID.randomUUID().toString()) // jti, unique JWT token identifier

										// signature
										.signWith(hmacKey)
										.setHeaderParam("typ","JWT")

										// finalize
										.compact();

								LOGGER.info("Created JWT token for wallet " + address + ", token: " + jwtToken);

							}
						} else {
							LOGGER.warn("Unsuccessful authentication attempt for wallet " + address);
							authmessage = "Unsuccessful authentication attempt for wallet " + address;
							authcode = 405;
							success = false;
						}
					}
				} else {
					LOGGER.info("v1_authz() called with invalid address=" + req.getAddress());
					return Response
							.status(403)
							.header("Access-Control-Allow-Origin", "*")
							.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
							.header("Access-Control-Allow-Credentials", "true")
							.header("Access-Control-Allow-Methods", "GET, POST")
							.header("Access-Control-Max-Age", "1209600")
							.entity("Access Denied, invalid address specified")
							.build();
				}

			} else {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Access Denied, invalid IP")
						.build();
			}

		} else {
			LOGGER.warn("Invalid POST request noted: " + reqSTR);
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}
		ForestFishV1Response_authenticate pb = new ForestFishV1Response_authenticate(address, success, authcode, authmessage, jwtToken);
		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				.header("Access-Control-Max-Age", "1209600")
				.entity(JSONUtils.createJSONFromPOJO(pb))
				.build();
	}

	// curl -s -X POST "localhost:6969/api/forestfish/v1/policyupdate" -H 'Content-Type: application/json' --header "X-Secret: thesecret" -d '{"accounts":{"0x12890d2cce102216644c59dae5baed380d84830c":"CONTRIBUTOR"},"allowedCC":{"ALL":true},"blockchains_enabled":{"POLYGON":true,"ETHEREUM":true}}'
	@POST
	@Path("/v1/policyupdate")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_policyupdate(@HeaderParam("X-Real-IP") String xrealIP, @HeaderParam("X-Secret") String secret, @Context HttpServletRequest request, String reqSTR) {
		LOGGER.info("v1_policyupdate()");

		Policy new_policy = JSONUtils.createPOJOFromJSON(reqSTR, Policy.class);
		if (null != new_policy) {
			String remoteIP = request.getRemoteAddr();
			if ("[0:0:0:0:0:0:0:1]".equals(remoteIP)) remoteIP = "127.0.0.1";

			if (null != xrealIP) {
				if (NetUtils.isValidIPV4(xrealIP)) {
					remoteIP = xrealIP;
				}
			}

			if (null == secret) {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Policy updates requires a secret to be provided")
						.build();
			}

			if (!ForestFishService.isAllow_policy_reconfig_over_rest()) {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Policy updates not allowed")
						.build();
			}

			if (NetUtils.isValidIPV4(remoteIP)) {
				String cc = ForestFishService.lookupCountryCodeForIP(remoteIP);
				if (ForestFishService.isAllow_policy_reconfig_over_rest_from_rfc1918()) {
					if (("RFC1918".equals(cc) || "LOCALHOST".equals(cc))) {
						// ok
					} else {
						LOGGER.warn("Attempt to update policy using non RFC1918 address: " + remoteIP + " (cc:" + cc + ")");
						return Response
								.status(403)
								.header("Access-Control-Allow-Origin", "*")
								.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
								.header("Access-Control-Allow-Credentials", "true")
								.header("Access-Control-Allow-Methods", "GET, POST")
								.header("Access-Control-Max-Age", "1209600")
								.entity("Policy updates not allowed from non RFC1918")
								.build();
					}
				}
				LOGGER.info("v1_policyupdate() called with address=" + remoteIP + " cc=" + cc + " policyupdatesallowed: " + ForestFishService.isAllow_policy_reconfig_over_rest() + " rfc1918 restriction: " + ForestFishService.isAllow_policy_reconfig_over_rest_from_rfc1918() + " cc:" + cc);

			} else {
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Access Denied, invalid IP")
						.build();
			}

		} else {
			LOGGER.warn("Invalid POST request noted: " + reqSTR);
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}

		if (ForestFishService.getSecret().equals(secret)) {
			LOGGER.info("secret matches .. all good");

			// Sanity check new ADMIN accounts
			HashMap<String, Boolean> new_admin_accounts = new HashMap<>();
			if (null == new_policy.getAccounts()) {
				LOGGER.warn("No accounts provided in new policy, will deny the update");
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Request denied, No ADMIN account provided in new policy")
						.build();
			} else {
				for (String account: new_policy.getAccounts().keySet()) {
					Role role = new_policy.getAccounts().get(account);
					if (role == Role.ADMIN) new_admin_accounts.put(account, true);
				}
			}

			if (new_admin_accounts.isEmpty()) {
				LOGGER.warn("No ADMIN account provided in new policy, will deny the update");
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Request denied, No ADMIN account provided in new policy")
						.build();
			}

			// Grab existing ADMIN accounts
			HashMap<String, Boolean> existing_admin_accounts = new HashMap<>();
			if (null != ForestFishService.getPolicy().getAccounts()) {
				for (String account: ForestFishService.getPolicy().getAccounts().keySet()) {
					Role role = new_policy.getAccounts().get(account);
					if (role == Role.ADMIN) existing_admin_accounts.put(account, true);
				}
			} else {
				LOGGER.warn("No existing ADMIN accounts? Aborting ..");
			}

			boolean admin_accounts_align = false;
			if (new_admin_accounts.size() > 0) {
				if (new_admin_accounts.size() == existing_admin_accounts.size()) {
					admin_accounts_align = true;
					for (String existing_admin_account: existing_admin_accounts.keySet()) {
						if (null == new_admin_accounts.get(existing_admin_account)) {
							LOGGER.warn("Existing admin account " + existing_admin_account + " seems to have been removed?");
							admin_accounts_align = false;
						}
					}
				} else {
					LOGGER.warn("The number of admin accounts does not add up");
				}
			} else {
				LOGGER.warn("New policy does not have at least one ADMIN account");
			}

			if (admin_accounts_align) {
				LOGGER.info("ADMIN account match, will proceed with the update");
				
				// Update running instance with new policy
				Policy updated_policy = ForestFishService.getPolicy();
				updated_policy.setAccounts(new_policy.getAccounts());
				ForestFishService.setPolicy(updated_policy);
				LOGGER.info("Running ForestFISHd instance has been updated");
				
				// Flush new policy to disk
				String json = JSONUtils.createJSONFromPOJO(updated_policy);
				FilesUtils.writeToFileUNIXNoException(json, "ffpolicy.json");
				LOGGER.info("New ForestFISHd policy flushed to disk");
				
				return Response
						.status(200)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Success")
						.build();
				
			} else {
				LOGGER.warn("ADMIN account mismatch, will deny the update");
				return Response
						.status(403)
						.header("Access-Control-Allow-Origin", "*")
						.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
						.header("Access-Control-Allow-Credentials", "true")
						.header("Access-Control-Allow-Methods", "GET, POST")
						.header("Access-Control-Max-Age", "1209600")
						.entity("Request denied, ADMIN account mismatch")
						.build();
			}
		} else {
			LOGGER.warn("Provided secret does not match!");
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}

	}
	
	// CORS, https://localcoder.org/how-to-enable-cross-domain-requests-on-jax-rs-web-services
	@OPTIONS
	@Path("/v1/ping")
	public Response ping_options() {
		LOGGER.info("OPTIONS req for /v1/ping");
		return Response.ok("")
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.build();
	}

	// CORS, https://localcoder.org/how-to-enable-cross-domain-requests-on-jax-rs-web-services
	@OPTIONS
	@Path("/v1/authn")
	public Response authn_options() {
		LOGGER.info("OPTIONS req for /v1/authn");
		return Response.ok("")
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.build();
	}

	// CORS, https://localcoder.org/how-to-enable-cross-domain-requests-on-jax-rs-web-services
	@OPTIONS
	@Path("/v1/authz")
	public Response authz_options() {
		LOGGER.info("OPTIONS req for /v1/authz");
		return Response.ok("")
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.build();
	}

	@GET
	@Path("/v1/protectedcontent/{contentid}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response v1_getprotected(@PathParam("contentid") String contentid, @HeaderParam(HttpHeaders.USER_AGENT) String userAgent, @HeaderParam(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
		contentid = contentid.toLowerCase();
		boolean valid = false;
		String content = "";
		String jwtToken = "";

		if (null != authorizationHeader) {
			if (authorizationHeader.contains("Bearer ")) {
				String jwtString = authorizationHeader.split(" ")[1];
				LOGGER.info("Received jwt: " + jwtString);

				String jwt_secret = ForestFishService.getSecret();
				JWTSignedDecodeResult jwt_decoderesult = JWTUtils.decodeAndVerifyJWTUsingSecretKey(jwtString, jwt_secret, SignatureAlgorithm.HS256.getJcaName());

				// DEBUG
				/*
				System.out.println("jwt_decoderesult.isSignature_valid(): " + jwt_decoderesult.isSignature_valid());
				System.out.println("jwt_decoderesult.isInvalid_jwt(): " + jwt_decoderesult.isInvalid_jwt());
				System.out.println("jwt_decoderesult.isExpired(): " + jwt_decoderesult.isExpired());
				System.out.println("jwt_decoderesult.getRegistered_claims(): " + jwt_decoderesult.getRegistered_claims().toString());
				System.out.println("jwt_decoderesult.getPublic_claims(): " + jwt_decoderesult.getPublic_claims().toString());
				System.out.println("jwt_decoderesult.getPrivate_claims(): " + jwt_decoderesult.getPrivate_claims().toString());
				 */

				if (true &&
						jwt_decoderesult.isSignature_valid() && 
						!jwt_decoderesult.isInvalid_jwt() && 
						!jwt_decoderesult.isExpired() && 
						(jwt_decoderesult.getToken_type() == TokenType.AUTHZ) && // Make sure token is AUTHZ
						true) {
					valid = true;
				}

			} else {
				LOGGER.warn("Protected content request with Authorization header but no JWT token present");
			}
		} else {
			LOGGER.warn("Protected content request without JWT token present in the Authorization header");
		}

		if (valid) {
			content = "this is secret";
		} else {
			LOGGER.warn("Attempt to access contentid " + contentid + " without a valid JWT token: " + jwtToken);
			return Response
					.status(403)
					.header("Access-Control-Allow-Origin", "*")
					.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
					.header("Access-Control-Allow-Credentials", "true")
					.header("Access-Control-Allow-Methods", "GET, POST")
					.header("Access-Control-Max-Age", "1209600")
					.entity("Access Denied, please behave")
					.build();
		}

		ForestFishV1Response_protectedcontent protecteContent = new ForestFishV1Response_protectedcontent(contentid, "text/html", content, valid);
		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
				.header("Access-Control-Max-Age", "1209600")
				.entity(JSONUtils.createJSONFromPOJO(protecteContent))
				.build();
	}

}
