const axios = require('axios')
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet
const sha256 = bitcoin.crypto.sha256
const signetBaseUrl = "https://mempool.space/signet/api"

const validator = (
  pubkey,
  msghash,
  signature,
) => ECPair.fromPublicKey(pubkey).verify(msghash, signature)


async function main() {
  // Create wallet
  const pkWIF = process.env.PK_TEST
  const myKeypair = ECPair.fromWIF(pkWIF, network)

  const { address: myAddress } = bitcoin.payments.p2pkh({
    pubkey: myKeypair.publicKey, network
  })
  console.log("Your address: ", myAddress)

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  // Information about txid1
  const txid1 = "64aa5e471a89e1b92472f474df06ff36d8208e5af73b20a63e965de44c6be0c0"
  const lockAmount = 2000
  const secret = Buffer.from('hi')
  // const hashLockScript = bitcoin.script.compile([
  //   bitcoin.opcodes.OP_SHA256,
  //   sha256(secret),
  //   bitcoin.opcodes.OP_EQUAL,
  // ])
  url = `${signetBaseUrl}/tx/${txid1}/hex`
  response = await fetch(url)
  const txHex1 = await response.text()
  console.log("\nThe hex string of HTLC utxo:", txHex1.slice(0, 32) + '...')

  // Construct the second transaction
  const psbt2 = new bitcoin.Psbt({ network })
  psbt2.addInput({
    hash: txid1,
    index: 0,
    // witnessUtxo: {
    //   script: hashLockScript,
    //   value: lockAmount,
    // },
    nonWitnessUtxo: Buffer.from(txHex1, 'hex'),
    // witnessScript: hashLockScript,
    redeemScript: bitcoin.script.compile([
      secret
    ])
  })
  psbt2.addOutput({
    address: myAddress,
    value: lockAmount - 200,
  })
  psbt2.signInput(0, myKeypair)
  psbt2.validateSignaturesOfInput(0)
  psbt2.finalizeAllInputs()

  const txHex2 = psbt2.extractTransaction().toHex()
  console.log("\nConstruct the second transaction:", txHex2)

  // Send the second transaction
  url = `${signetBaseUrl}/tx`
  response = await axios.post(url, txHex2, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })
  console.log("\nNew tx hash: ", response.data)
  const txid2 = response.data
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid2}`)
  console.log("\nFinished!")
}

main()
