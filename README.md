## FORESTFISHD

PoC API wrapper daemon for Java web3 library 'forestfish'. The /challenge and /authenticate API endpoints can be used to get NFT and ERC20 ownership as claims in an issued JWT token (ie used for NFT or token gated access).

![alt text](https://github.com/p00temkin/forestfishd/blob/master/img/forestfishd.png?raw=true)

### Building the application

[Java 17+, Maven 3.x]

   ```
   git clone https://github.com/p00temkin/forestfish
   mvn clean package install
   git clone https://github.com/p00temkin/forestfishd
   mvn clean package
   java -jar ./target/forestfishd-0.0.1-SNAPSHOT-jar-with-dependencies.jar
   ```

### Docker

   ```
   docker build -t forestfishd .
   docker run -d -p 6969:6969 forestfishd
   ```

### Get a login challenge from running daemon

   ```
   curl -s -X GET "localhost:6969/api/forestfish/v1/challenge/0x0491A1417bA71A5d9d69B8d99b46ced6F3dd8e9e"
   ```

### Sign a login challenge and get a JWT token back

   ```
 Credentials cred = ..
   
 // Get the challenge
 String jsonChallengeRESP = HttpRequestUtils.getBodyUsingGETUrlRequest("http://localhost:6969/api/forestfish/v1/getchallenge/" + cred.getAddress());
 ForestFishV1Response_challenge challengeResp = JSONUtils.createForestFishV1Response_challenge(jsonChallengeRESP);
 
 // Sign challenge using our account
 String signature = EVMUtils.sign(cred, challengeResp.getChallenge());

 // Get a JWT token back
 ForestFishV1Request_authenticate authREQ = new ForestFishV1Request_authenticate(challengeResp.getChallenge(), signature, challengeResp.getAddress());
 String jsonAuthReqJSON = JSONUtils.createJSONFromV1ForestFishAuthenticateRequest(authREQ);
 String jsonAuthenticateRESP = HttpRequestUtils.getBodyUsingUrlPOSTRequestWithJsonBody("http://localhost:6969/api/forestfish/v1/authenticate", jsonAuthReqJSON);
 System.out.println("Our JWT token: " + authResponse.getJwtToken());
   ```

### Support/Donate

To support this project directly:

   ```
   Ethereum/EVM: forestfish.x / 0x207d907768Df538F32f0F642a281416657692743
   Algorand: forestfish.x / 3LW6KZ5WZ22KAK4KV2G73H4HL2XBD3PD3Z5ZOSKFWGRWZDB5DTDCXE6NYU
   ```

Or please consider donating to EFF:
[Electronic Frontier Foundation](https://supporters.eff.org/donate)
