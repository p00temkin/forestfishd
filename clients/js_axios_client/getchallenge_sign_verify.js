const axios = require('axios');
const Web3 = require('web3');

const providerurl = 'https://rpc-mainnet.matic.quiknode.pro';
const web3Provider = new Web3.providers.HttpProvider(providerurl);
const web3 = new Web3(web3Provider);

// https://hukenneth.medium.com/ethereum-using-web3-js-for-message-signing-7e2935b2958c [0x12890D2cce102216644c59daE5baed380d84830c]
const privateKey = '0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7';
account = web3.eth.accounts.privateKeyToAccount(privateKey.toString('hex'));
console.log('our account address: ' + account.address);

async function makeGetRequest(url) {
  let res = await axios.get(url);
  let data = res.data;
  return data.challenge;
}

async function makePostRequest(url, payload) {
  let res = await axios.post(url, payload, { headers: { 'Content-Type': 'application/json' } });
  let data = res.data;
  return data;
}

console.log("REST init()");
(async function() {
  const cha = await makeGetRequest('http://localhost:6969/api/forestfish/v1/getchallenge/' + account.address);
  console.log("got challenge: " + cha);

  const sig = web3.eth.accounts.sign(cha, privateKey);
  console.log("sig.message: " + sig.message);
  console.log("sig.signature: " + sig.signature);

  let payload = { version: "v1", challenge: cha, signature: sig.signature, address: account.address } ;
  console.log(payload);
  const auth = await makePostRequest('http://localhost:6969/api/forestfish/v1/authenticate', payload);
  console.log('success: ' + auth.success);
})();


