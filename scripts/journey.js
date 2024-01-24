const axios = require('axios');
const bitcoin = require('bitcoinjs-lib')
const bs58 = require('bs58')
const https = require('https');
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet
const signetBaseUrl = "https://mempool.space/signet/api"

const validator = (
  pubkey,
  msghash,
  signature,
) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);


async function main() {
  // Create wallet
  const pkWIF = process.env.PK_TEST
  const keypair = ECPair.fromWIF(pkWIF, network)

  const { address } = bitcoin.payments.p2pkh({
    pubkey: keypair.publicKey, network
  })
  console.log("Your address: ", address)

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  // Get UTXOs
  let url, response, data
  url = `${signetBaseUrl}/address/${address}/utxo`
  response = await fetch(url)
  data = await response.json()
  let availableUtxos = data.filter(x => x.value > 10000)
  if (availableUtxos.length == 0)
    throw new Error("No available UTXO!")
  let utxo = availableUtxos[0]
  console.log("We use this utxo: ", utxo.txid)

  // Get the detailed tx (hex)
  url = `${signetBaseUrl}/tx/${utxo.txid}/hex`
  response = await fetch(url)
  let txHex = await response.text()
  console.log("\nThe hex string of this utxo:", txHex)

  // Construct a transaction
  const psbt = new bitcoin.Psbt({ network: network })
  psbt.addInput({
    hash: utxo.txid,
    index: utxo.vout,
    nonWitnessUtxo: Buffer.from(txHex, 'hex')
  })
  psbt.addOutput({
    address: address,
    value: utxo.value - 200,
  })
  psbt.signInput(0, keypair)
  psbt.validateSignaturesOfInput(0, validator)
  psbt.finalizeAllInputs()
  let newTxHex = psbt.extractTransaction().toHex()
  console.log("\nConstruct the transaction:", newTxHex)

  // Send the transaction
  url = `${signetBaseUrl}/tx`
  response = await axios.post(url, newTxHex, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })
  console.log("\nNew tx hash: ", response.data);
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${response.data}`)
  
  console.log("\nFinished!")
}

main()
