package crypto.forestfish.forestfishd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.junit.Ignore;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_challenge;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_knockknock;
import crypto.forestfish.forestfishd.model.policy.Policy;
import crypto.forestfish.forestfishd.model.policy.Role;
import crypto.forestfish.forestfishd.singletons.ApiService;
import crypto.forestfish.forestfishd.singletons.ForestFishService;
import crypto.forestfish.objects.jwt.JWTSignedDecodeResult;
import crypto.forestfish.objects.jwt.JWTUnsignedDecodeResult;
import crypto.forestfish.objects.jwt.TokenType;
import crypto.forestfish.utils.EVMUtils;
import crypto.forestfish.utils.HttpRequestUtils;
import crypto.forestfish.utils.JSONUtils;
import crypto.forestfish.utils.JWTUtils;
import crypto.forestfish.utils.StringsUtils;
import io.jsonwebtoken.SignatureAlgorithm;

public class ForestFishV1RestServiceTest {

	@Test
	public void testE2E_authN() {

		Settings settings = new Settings();

		// Launch a GitGo singleton if needed
		ForestFishService.getInstance(settings, null);

		// Launch an ApiService singleton if needed
		ApiService.getInstance(6969);

		// /v1/status
		System.out.println("");
		assertEquals("Ensure ok /v1/status reply", "{\"status\":\"up\",\"version\":\"v1\"}", HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/status"));

		// https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
		String privateKey1 = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
		String walletAddress = "0x12890d2cce102216644c59dae5baed380d84830c";
		Credentials credentials = Credentials.create(privateKey1);
		assertEquals("Ensure correct ETH address", walletAddress, credentials.getAddress());

		// /v1/getchallenge
		System.out.println("");
		System.out.println("Making request: " + "http://localhost:6969/api/forestfish/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		String jsonChallengeRESP = HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		System.out.println("Got challenge response: " + jsonChallengeRESP);
		ForestFishV1Response_challenge challengeResp = JSONUtils.createPOJOFromJSON(jsonChallengeRESP, ForestFishV1Response_challenge.class);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", challengeResp.getAddress());
		assertTrue("Ensure we are getting a valid challenge", challengeResp.getChallenge().length() > 0);

		// Sign using our wallet
		String signature = EVMUtils.sign(credentials, challengeResp.getChallenge());

		// v1/authn by sending the signed message back
		System.out.println("");
		ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
		String jsonAuthReqJSON = JSONUtils.createJSONFromPOJO(authREQ);
		System.out.println("Making authenticate request: " + jsonAuthReqJSON);
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authn", jsonAuthReqJSON);
		System.out.println("Got authenticate response: " + jsonAuthenticateRESP);
		assertTrue("Ensure we got a valid body response", jsonAuthenticateRESP.length()>10);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
		assertEquals("Ensure we are get authcode 200", 200, authResponse.getAuthcode());

		// verify JWT fields (no signature)
		System.out.println("");
		System.out.println("Our JWT token is: " + authResponse.getJwtToken());
		assertTrue("Ensure sane JWT token", authResponse.getJwtToken().split("\\.").length == 3);
		JWTUnsignedDecodeResult jwtnosig = JWTUtils.decodeJWT(authResponse.getJwtToken());
		assertEquals("Ensure alg is HS256", "HS256", jwtnosig.getAlg());
		assertEquals("Ensure typ is JWT", "JWT", jwtnosig.getTyp());
		assertEquals("Ensure iss is forestfishd", "forestfishd", jwtnosig.getIss());

		// verify JWT signature
		JWTSignedDecodeResult jwt_decoderesult = JWTUtils.decodeAndVerifyJWTUsingSecretKey(authResponse.getJwtToken(), ForestFishService.getSecret(), SignatureAlgorithm.HS256.getJcaName());
		assertTrue("jwt_decoderesult.isSignature_valid()", jwt_decoderesult.isSignature_valid());
		assertFalse("jwt_decoderesult.isInvalid_jwt()", jwt_decoderesult.isInvalid_jwt());
		assertFalse("jwt_decoderesult.isExpired()", jwt_decoderesult.isExpired());
		
		// verify JWT registered claims (with signature)
		assertEquals("Ensure iss is forestfishd", "forestfishd", jwt_decoderesult.getRegistered_claims().getIss());
		assertEquals("Ensure aud is web3did", "web3did", jwt_decoderesult.getRegistered_claims().getAud());
		assertEquals("Ensure sub is the wallet address", walletAddress, jwt_decoderesult.getRegistered_claims().getSub());
		assertTrue("Ensure jti is a valid UUID", StringsUtils.isValidUUID(jwt_decoderesult.getRegistered_claims().getJti()));

		// verify JWT public claims are blank
		assertEquals("Ensure name is blank", null, jwt_decoderesult.getPublic_claims().getName());
		assertEquals("Ensure given_name is blank", null, jwt_decoderesult.getPublic_claims().getGiven_name());
		assertEquals("Ensure middle name is blank", null, jwt_decoderesult.getPublic_claims().getMiddle_name());
		assertEquals("Ensure family_name is blank", null, jwt_decoderesult.getPublic_claims().getFamily_name());
		
		// verify JWT private claims properly set
		assertEquals("Ensure evm_wallet is set", walletAddress, jwt_decoderesult.getPrivate_claims().getEvm_wallet_address());
		assertEquals("Ensure token_type is AUTHN", "AUTHN", jwt_decoderesult.getPrivate_claims().getToken_type());
		assertEquals("Ensure no role is set for AUTHN", null, jwt_decoderesult.getPrivate_claims().getRole());
		
		// Make sure private token_type claim has propagated to the root
		assertEquals("Ensure root token_type is AUTHN", TokenType.AUTHN, jwt_decoderesult.getToken_type());

		// Attempt to get access to the content using AUTHN but fail
		String jsonGrabProtectedContentRESP = HttpRequestUtils.getBodyUsingGETUrlRequestAndJWTToken("http://localhost:6969/api/forestfish/v1/protectedcontent/1", authResponse.getJwtToken());
		assertTrue("Ensure we did not get a valid body response", jsonGrabProtectedContentRESP.length() == 0);
		
		// /v1/knockknock
		String knockjson = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/knockknock", "{\"address\":\"" + walletAddress + "\",\"version\":\"v1\"}");
		System.out.println("knockknockjson: " + knockjson);
		ForestFishV1Response_knockknock knockResponse = JSONUtils.createPOJOFromJSON(knockjson, ForestFishV1Response_knockknock.class);
		assertEquals("Ensure ok /v1/knockknock wallet reply", walletAddress, knockResponse.getWallet());
		assertEquals("Ensure ok /v1/knockknock negative preregistered reply", false, knockResponse.getPreregistered());
	}

	@Test
	public void testE2E_authZ() {

		Settings settings = new Settings();
		settings.setNftmode(true);
		settings.setTokenmode(true);
		
		Policy ffpolicy = new Policy();
		HashMap<String, Role> accounts = new HashMap<>();
		accounts.put("0x12890d2cce102216644c59dae5baed380d84830c", Role.CONSUMER);
		accounts.put("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", Role.ADMIN);
		ffpolicy.setAccounts(accounts);
		HashMap<String, Boolean> ccs = new HashMap<>();
		ccs.put("ALL", true);
		HashMap<String, Boolean> blockchains_enabled = new HashMap<>();
		blockchains_enabled.put("POLYGON", true);
		blockchains_enabled.put("ETHEREUM", true);
		ffpolicy.setAllowedCC(ccs);

		// Launch a GitGo singleton if needed
		ForestFishService.getInstance(settings, ffpolicy);

		// Launch an ApiService singleton if needed
		ApiService.getInstance(6969);

		// /v1/status
		System.out.println("");
		assertEquals("Ensure ok /v1/status reply", "{\"status\":\"up\",\"version\":\"v1\"}", HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/status"));

		// https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
		String privateKey1 = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
		String walletAddress = "0x12890d2cce102216644c59dae5baed380d84830c";
		Credentials credentials = Credentials.create(privateKey1);
		assertEquals("Ensure correct ETH address", walletAddress, credentials.getAddress());

		// /v1/getchallenge
		System.out.println("");
		System.out.println("Making request: " + "http://localhost:6969/api/forestfish/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		String jsonChallengeRESP = HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		System.out.println("Got challenge response: " + jsonChallengeRESP);
		ForestFishV1Response_challenge challengeResp = JSONUtils.createPOJOFromJSON(jsonChallengeRESP, ForestFishV1Response_challenge.class);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", challengeResp.getAddress());
		assertTrue("Ensure we are getting a valid challenge", challengeResp.getChallenge().length() > 0);

		// Sign using our wallet
		String signature = EVMUtils.sign(credentials, challengeResp.getChallenge());

		// v1/authz by sending the signed message back
		System.out.println("");
		ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
		String jsonAuthReqJSON = JSONUtils.createJSONFromPOJO(authREQ);
		System.out.println("Making authenticate request: " + jsonAuthReqJSON);
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authz", jsonAuthReqJSON);
		System.out.println("Got authenticate response: " + jsonAuthenticateRESP);
		assertTrue("Ensure we got a valid body response", jsonAuthenticateRESP.length()>10);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
		assertEquals("Ensure we are get authcode 200", 200, authResponse.getAuthcode());

		// verify JWT fields (no signature)
		System.out.println("");
		System.out.println("Our JWT token is: " + authResponse.getJwtToken());
		assertTrue("Ensure sane JWT token", authResponse.getJwtToken().split("\\.").length == 3);
		JWTUnsignedDecodeResult jwtnosig = JWTUtils.decodeJWT(authResponse.getJwtToken());
		assertEquals("Ensure alg is HS256", "HS256", jwtnosig.getAlg());
		assertEquals("Ensure typ is JWT", "JWT", jwtnosig.getTyp());
		assertEquals("Ensure iss is forestfishd", "forestfishd", jwtnosig.getIss());

		// verify JWT signature
		JWTSignedDecodeResult jwt_decoderesult = JWTUtils.decodeAndVerifyJWTUsingSecretKey(authResponse.getJwtToken(), ForestFishService.getSecret(), SignatureAlgorithm.HS256.getJcaName());
		assertTrue("jwt_decoderesult.isSignature_valid()", jwt_decoderesult.isSignature_valid());
		assertFalse("jwt_decoderesult.isInvalid_jwt()", jwt_decoderesult.isInvalid_jwt());
		assertFalse("jwt_decoderesult.isExpired()", jwt_decoderesult.isExpired());
		
		// verify JWT registered claims (with signature)
		assertEquals("Ensure iss is forestfishd", "forestfishd", jwt_decoderesult.getRegistered_claims().getIss());
		assertEquals("Ensure aud is web3did", "web3did", jwt_decoderesult.getRegistered_claims().getAud());
		assertEquals("Ensure sub is the wallet address", walletAddress, jwt_decoderesult.getRegistered_claims().getSub());
		assertTrue("Ensure jti is a valid UUID", StringsUtils.isValidUUID(jwt_decoderesult.getRegistered_claims().getJti()));

		// verify JWT public claims are blank
		assertEquals("Ensure name is blank", null, jwt_decoderesult.getPublic_claims().getName());
		assertEquals("Ensure given_name is blank", null, jwt_decoderesult.getPublic_claims().getGiven_name());
		assertEquals("Ensure middle name is blank", null, jwt_decoderesult.getPublic_claims().getMiddle_name());
		assertEquals("Ensure family_name is blank", null, jwt_decoderesult.getPublic_claims().getFamily_name());
		
		// verify JWT private claims properly set
		assertEquals("Ensure evm_wallet is set", walletAddress, jwt_decoderesult.getPrivate_claims().getEvm_wallet_address());
		assertEquals("Ensure token_type is AUTHZ", "AUTHZ", jwt_decoderesult.getPrivate_claims().getToken_type());
		assertEquals("Ensure no role is set for AUTHZ", Role.CONSUMER.toString(), jwt_decoderesult.getPrivate_claims().getRole());
		
		// Make sure private token_type claim has propagated to the root
		assertEquals("Ensure root token_type is AUTHZ", TokenType.AUTHZ, jwt_decoderesult.getToken_type());

		// Attempt to get access to the content using AUTHN and succeed
		String jsonGrabProtectedContentRESP = HttpRequestUtils.getBodyUsingGETUrlRequestAndJWTToken("http://localhost:6969/api/forestfish/v1/protectedcontent/1", authResponse.getJwtToken());
		System.out.println("");
		System.out.println("The secret content:");
		System.out.println(jsonGrabProtectedContentRESP);
		assertEquals("Ensure we obtained the secret content", "{\"content\":\"this is secret\",\"contentid\":\"1\",\"contenttype\":\"text/html\",\"valid\":true,\"version\":\"v1\"}", jsonGrabProtectedContentRESP);
	
		// /v1/knockknock
		String knockjson = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/knockknock", "{\"address\":\"" + walletAddress + "\",\"version\":\"v1\"}");
		ForestFishV1Response_knockknock knockResponse = JSONUtils.createPOJOFromJSON(knockjson, ForestFishV1Response_knockknock.class);
		assertEquals("Ensure ok /v1/knockknock wallet reply", walletAddress, knockResponse.getWallet());
		assertEquals("Ensure ok /v1/knockknock preregistered reply", true, knockResponse.getPreregistered());
	}
	
	@Ignore
	@Test
	public void testLocalhostServer_actAsClient() {

		// /v1/status
		assertEquals("Ensure ok /v1/status reply", "{\"status\":\"up\",\"version\":\"v1\"}", HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/status"));

		// https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
		String privateKey1 = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
		Credentials credentials = Credentials.create(privateKey1);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", credentials.getAddress());

		// /v1/challenge
		System.out.println("Making request: " + "http://localhost:6969/api/gitgo/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		String jsonChallengeRESP = HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/getchallenge/" + credentials.getAddress());
		System.out.println(jsonChallengeRESP);
		ForestFishV1Response_challenge challengeResp = JSONUtils.createPOJOFromJSON(jsonChallengeRESP, ForestFishV1Response_challenge.class);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", challengeResp.getAddress());
		assertTrue("Ensure we are getting a valid challenge", challengeResp.getChallenge().length() > 0);

		// Sign using our wallet
		String signature = EVMUtils.sign(credentials, challengeResp.getChallenge());

		// v1/authenticate by sending the signed message back
		ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
		String jsonAuthReqJSON = JSONUtils.createJSONFromPOJO(authREQ);
		System.out.println(jsonAuthReqJSON);
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authn", jsonAuthReqJSON);
		System.out.println(jsonAuthenticateRESP);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertFalse("Ensure non-null response", null == authResponse);
		if (null != authResponse) {
			assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
			System.out.println("Our JWT token: " + authResponse.getJwtToken());
		}

	}

}
