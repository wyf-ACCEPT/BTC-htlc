const axios = require('axios')
const bip65 = require('bip65')
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

function cltvCheckSigOutput(
  aQ,
  bQ,
  lockTime,
) {
  return bitcoin.script.fromASM(
    `
    OP_IF
        ${bitcoin.script.number.encode(lockTime).toString('hex')}
        OP_CHECKLOCKTIMEVERIFY
        OP_DROP
    OP_ELSE
        ${bQ.publicKey.toString('hex')}
        OP_CHECKSIGVERIFY
    OP_ENDIF
    ${aQ.publicKey.toString('hex')}
    OP_CHECKSIG
  `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function utcNow() {
  return Math.floor(Date.now() / 1000);
}

async function main() {
  // Create wallet
  const pkWIF = process.env.PK_TEST
  const alice = ECPair.fromWIF(pkWIF, network)
  const bob = ECPair.fromWIF(pkWIF, network)

  const { address: aliceAddress } = bitcoin.payments.p2pkh({
    pubkey: alice.publicKey, network
  })
  const { address: bobAddress } = bitcoin.payments.p2pkh({
    pubkey: bob.publicKey, network
  })

  console.log("Alice's address: ", aliceAddress)
  console.log("Bob's address: ", bobAddress)

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  // 3 hours ago (ref: bitcoinjslib-cltv.spec.ts)
  const lockAmount = 2000
  const lockTime = bip65.encode({ utc: utcNow() - 3600 * 3 });
  const redeemScript = cltvCheckSigOutput(alice, alice, lockTime);
  const { address: p2shAddress } = bitcoin.payments.p2sh({
    redeem: { output: redeemScript, network },
    network,
  })
  console.log("\nThe P2SH address:", p2shAddress)

  // Get UTXOs
  let url, response, data
  url = `${signetBaseUrl}/address/${aliceAddress}/utxo`
  response = await fetch(url)
  data = await response.json()
  const availableUtxos = data.filter(x => x.value > 10000)
  if (availableUtxos.length == 0)
    throw new Error("No available UTXO!")
  let utxo0 = availableUtxos[0]
  console.log("\nWe use this utxo: ", utxo0.txid)

  // Get the detailed tx (hex)
  url = `${signetBaseUrl}/tx/${utxo0.txid}/hex`
  response = await fetch(url)
  const txHex0 = await response.text()
  console.log("\nThe hex string of this utxo:", txHex0.slice(0, 32) + '...')

  // Construct the first transaction
  const psbt1 = new bitcoin.Psbt({ network })
  psbt1.addInput({
    hash: utxo0.txid,
    index: utxo0.vout,
    nonWitnessUtxo: Buffer.from(txHex0, 'hex'),
  })
  psbt1.addOutput({
    address: p2shAddress,
    value: lockAmount,
  })
  psbt1.addOutput({
    address: aliceAddress,
    value: utxo0.value - lockAmount - 300
  })
  psbt1.signInput(0, alice)
  psbt1.validateSignaturesOfInput(0, validator)
  psbt1.finalizeAllInputs()
  const txHex1 = psbt1.extractTransaction().toHex()
  console.log("\nConstruct the first transaction:", txHex1)

  // Send the first transaction
  url = `${signetBaseUrl}/tx`
  response = await axios.post(url, txHex1, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })
  const txid1 = response.data
  console.log("\nNew tx hash: ", txid1)
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid1}`)
  console.log("\nFinished!")

  // constrcut the second tx
  const tx2 = new bitcoin.Transaction()
  tx2.locktime = lockTime
  tx2.addInput(Buffer.from(txid1, 'hex').reverse(), 0, 0xfffffffe)
  tx2.addOutput(bitcoin.address.toOutputScript(aliceAddress, network), lockAmount - 300)

  // {Alice's signature} OP_TRUE
  const hashType = bitcoin.Transaction.SIGHASH_ALL
  const signatureHash = tx2.hashForSignature(0, redeemScript, hashType);
  const redeemScriptSig = bitcoin.payments.p2sh({
    redeem: {
      input: bitcoin.script.compile([
        bitcoin.script.signature.encode(
          alice.sign(signatureHash),
          hashType,
        ),
        bitcoin.opcodes.OP_TRUE,
      ]),
      output: redeemScript,
    },
  }).input;
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
