package crypto.forestfish.forestfishd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Ignore;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_challenge;
import crypto.forestfish.forestfishd.singletons.ApiService;
import crypto.forestfish.forestfishd.singletons.ForestFishService;
import crypto.forestfish.utils.EVMUtils;
import crypto.forestfish.utils.HttpRequestUtils;
import crypto.forestfish.utils.JSONUtils;

public class ForestFishV1RestServiceTest {

	@Test
	public void testE2E() {
		
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
		Credentials credentials = Credentials.create(privateKey1);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", credentials.getAddress());

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

		// v1/authenticate by sending the signed message back
		System.out.println("");
		ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
		String jsonAuthReqJSON = JSONUtils.createJSONFromPOJO(authREQ);
		System.out.println("Making authenticate request: " + jsonAuthReqJSON);
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authenticate", jsonAuthReqJSON);
		System.out.println("Got authenticate response: " + jsonAuthenticateRESP);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
		
		System.out.println("");
		System.out.println("Our JWT token is: " + authResponse.getJwtToken());
		String jsonGrabProtectedContentRESP = HttpRequestUtils.getBodyUsingGETUrlRequestAndJWTToken("http://localhost:6969/api/forestfish/v1/protectedcontent/1", authResponse.getJwtToken());
		
		System.out.println("");
		System.out.println("The secret content:");
		System.out.println(jsonGrabProtectedContentRESP);
		assertEquals("Ensure we obtained the secret content", "{\"content\":\"this is secret\",\"contentid\":\"1\",\"contenttype\":\"text/html\",\"valid\":true,\"version\":\"v1\"}", jsonGrabProtectedContentRESP);
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
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authenticate", jsonAuthReqJSON);
		System.out.println(jsonAuthenticateRESP);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertFalse("Ensure non-null response", null == authResponse);
		if (null != authResponse) {
			assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
			System.out.println("Our JWT token: " + authResponse.getJwtToken());
		}

	}

	@Test
	public void testE2EWithNFTAndTokenMode() {
		
		Settings settings = new Settings();
		settings.setNftmode(true);
		settings.setTokenmode(true);
		
		// Launch a GitGo singleton if needed
		ForestFishService.getInstance(settings, null);
	
		// Launch an ApiService singleton if needed
		ApiService.getInstance(6969);
	
		// /v1/status
		System.out.println("");
		assertEquals("Ensure ok /v1/status reply", "{\"status\":\"up\",\"version\":\"v1\"}", HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/status"));
	
		// https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
		String privateKey1 = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
		Credentials credentials = Credentials.create(privateKey1);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", credentials.getAddress());
	
		// /v1/challenge
		System.out.println("");
		System.out.println("Making request: " + "http://localhost:6969/api/gitgo/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		String jsonChallengeRESP = HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/getchallenge/0x12890d2cce102216644c59dae5baed380d84830c");
		System.out.println("Got challenge response: " + jsonChallengeRESP);
		ForestFishV1Response_challenge challengeResp = JSONUtils.createPOJOFromJSON(jsonChallengeRESP, ForestFishV1Response_challenge.class);
		assertEquals("Ensure correct ETH address", "0x12890d2cce102216644c59dae5baed380d84830c", challengeResp.getAddress());
		assertTrue("Ensure we are getting a valid challenge", challengeResp.getChallenge().length() > 0);
	
		// Sign using our wallet
		String signature = EVMUtils.sign(credentials, challengeResp.getChallenge());
	
		// v1/authenticate by sending the signed message back
		System.out.println("");
		ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
		String jsonAuthReqJSON = JSONUtils.createJSONFromPOJO(authREQ);
		System.out.println("Making authenticate request: " + jsonAuthReqJSON);
		String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authenticate", jsonAuthReqJSON);
		System.out.println("Got authenticate response: " + jsonAuthenticateRESP);
		ForestFishV1Response_authenticate authResponse = JSONUtils.createPOJOFromJSON(jsonAuthenticateRESP, ForestFishV1Response_authenticate.class);
		assertTrue("Ensure we are successfully authenticated", authResponse.isSuccess());
		
		System.out.println("");
		System.out.println("The secret content:");
		String jsonGrabProtectedContentRESP = HttpRequestUtils.getBodyUsingGETUrlRequestAndJWTToken("http://localhost:6969/api/forestfish/v1/protectedcontent/1", authResponse.getJwtToken());
		System.out.println(jsonGrabProtectedContentRESP);
		assertEquals("Ensure we obtained the secret content", "{\"content\":\"this is secret\",\"contentid\":\"1\",\"contenttype\":\"text/html\",\"valid\":true,\"version\":\"v1\"}", jsonGrabProtectedContentRESP);
	}

}
