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
  const txid1 = "ba5fcd76e75017303b0b3273aa9ce2edd9326981e724592059d442311ecbd999"
  const lockAmount = 2000
  const secret = Buffer.from('hi')
  const hash = sha256(secret)
  const hashLockScript = bitcoin.script.compile([
    // bitcoin.opcodes.OP_SHA256,
    // bitcoin.script.number.encode(hash),
    hash,
    bitcoin.opcodes.OP_EQUAL,
  ])

  const hashLockScript2 = bitcoin.script.fromASM(
    `${hash.toString('hex')} OP_EQUAL`.trim()
    .replace(/\s+/g, ' ')
  )
  
  console.log(hashLockScript)
  console.log(hashLockScript2)

  url = `${signetBaseUrl}/tx/${txid1}/hex`
  response = await fetch(url)
  const txHex1 = await response.text()
  console.log("\nThe hex string of HTLC utxo:", txHex1.slice(0, 32) + '...')

  const p2shAddress = bitcoin.payments.p2sh({
    redeem: { output: hashLockScript, network },
    network,
  }).address
  console.log("\nThe P2SH address:", p2shAddress)

  // Redeem
  const redeemScriptSig = bitcoin.payments.p2sh({
    redeem: {
      input: bitcoin.script.compile([
        hash
      ]),
      output: hashLockScript,
    },
  }).input

  const tx2 = new bitcoin.Transaction()
  tx2.addInput(Buffer.from(txid1, 'hex').reverse(), 0)
  tx2.addOutput(bitcoin.address.toOutputScript(myAddress, network), lockAmount - 600)
  tx2.setInputScript(0, redeemScriptSig)
  const txHex2 = tx2.toHex()
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


// // Construct the second transaction
// const psbt2 = new bitcoin.Psbt({ network })
// psbt2.addInput({
//   hash: txid1,
//   index: 0,
//   // witnessUtxo: {
//   //   script: hashLockScript,
//   //   value: lockAmount,
//   // },
//   nonWitnessUtxo: Buffer.from(txHex1, 'hex'),
//   // witnessScript: hashLockScript,
//   redeemScript: bitcoin.script.compile([
//     secret
//   ])
// })
// psbt2.addOutput({
//   address: myAddress,
//   value: lockAmount - 200,
// })
// psbt2.signInput(0, myKeypair)
// psbt2.validateSignaturesOfInput(0)
// psbt2.finalizeAllInputs()

// const txHex2 = psbt2.extractTransaction().toHex()
// console.log("\nConstruct the second transaction:", txHex2)
