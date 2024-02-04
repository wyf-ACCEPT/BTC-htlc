const axios = require('axios')
const bip65 = require('bip65')
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
const { toXOnly } = require('bitcoinjs-lib/src/psbt/bip371')

require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet
const signetBaseUrl = "https://mempool.space/signet/api"
const sha256 = bitcoin.crypto.sha256
const validator = (pubkey, msghash, signature,) =>
  ECPair.fromPublicKey(pubkey).verify(msghash, signature)


function utcNow() {
  return Math.floor(Date.now() / 1000);
}

function getOutputScript(
  encodedSwapHex, expireTs, aliceAddressHex, bobAddressHex
) {
  return bitcoin.script.fromASM(
    /**
     * Branch 1: Bob unlock before `expireTs` using `secret`
     *           or using Alice's signature...?
     *     `OP_SHA256 <hash> OP_EQUALVERIFY`
     * ->  `<encodedSwap> OP_DROP OP_CHECKSIGVERIFY`
     * Branch 2: Alice unlock after `expireTs` directly
     */
    `
    OP_IF
      ${encodedSwapHex}
      OP_DROP
      
      OP_DUP 
        OP_HASH160
        ${bobAddressHex}
    OP_ELSE
      ${bitcoin.script.number.encode(expireTs).toString('hex')}
        OP_CHECKLOCKTIMEVERIFY
        OP_DROP
      OP_DUP 
        OP_HASH160
        ${aliceAddressHex}
    OP_ENDIF
    OP_EQUALVERIFY
    OP_CHECKSIG
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function getInputScriptBob(secret, bobPubkey, bobSignature) {
  return bitcoin.script.fromASM(
    `
    ${bobSignature.toString('hex')}
    ${bobPubkey.toString('hex')}
    ${secret.toString('hex')}
    OP_TRUE
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function getInputScriptAlice(alicePubkey, aliceSignature) {
  return bitcoin.script.fromASM(
    `
    ${aliceSignature.toString('hex')}
    ${alicePubkey.toString('hex')}
    OP_FALSE
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}


async function main() {
  // Load wallet
  const pkWIF1 = process.env.PK_TEST
  const pkWIF2 = process.env.PK_TEST2
  const alice = ECPair.fromWIF(pkWIF1, network)
  const bob = ECPair.fromWIF(pkWIF2, network)

  const { address: aliceAddress } = bitcoin.payments.p2pkh({
    pubkey: alice.publicKey, network
  })
  const aliceAddressHex = bitcoin.address
    .fromBase58Check(aliceAddress, network).hash.toString('hex')
  const { address: bobAddress } = bitcoin.payments.p2pkh({
    pubkey: bob.publicKey, network
  })
  const bobAddressHex = bitcoin.address
    .fromBase58Check(bobAddress, network).hash.toString('hex')

  console.log("Alice's P2PKH address: ", aliceAddress)
  console.log("Alice's P2PKH address (hex): ", aliceAddressHex)
  console.log("Bob's P2PKH address: ", bobAddress)
  console.log("Bob's P2PKH address (hex): ", bobAddressHex)

  const { output: aliceP2trScript, address: aliceAddressP2tr } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(alice.publicKey), network
  })
  const { output: bobP2trScript, address: bobAddressP2tr } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(bob.publicKey), network
  })
  console.log("\nAlice's P2TR address: ", aliceAddressP2tr)
  console.log("Bob's P2TR address: ", bobAddressP2tr)

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  /**
   * First transaction 
   * - Bob unlock before `expireTs` using `secret`
   * - Or Alice unlock after `expireTs` using `secret`
   */
  const lockAmount = 2000
  const expireTs = bip65.encode({ utc: utcNow() - 3600 * 2 })
  const secret = Buffer.from('hi')
  const hash = sha256(secret)
  const redeemScript = getOutputScript(hash, expireTs, aliceAddressHex, bobAddressHex)
  const { address: p2shAddress } = bitcoin.payments.p2sh({
    redeem: { output: redeemScript, network },
    network,
  })
  console.log("\nThe P2SH address:", p2shAddress)

  // Get UTXOs
  let url, response, data
  url = `${signetBaseUrl}/address/${aliceAddress}/utxo`
  response = await fetch(url); data = await response.json()
  const availableUtxos = data.filter(x => x.value > 10000)
  if (availableUtxos.length == 0) throw new Error("No available UTXO!")
  let utxo0 = availableUtxos[0]
  console.log("\nWe use this utxo: ", utxo0.txid)

  // Get the detailed tx (hex) of the utxo
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
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })
  const txid1 = response.data
  console.log("\nTx-1 hash: ", txid1)
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid1}`)

  /**
   * Construct the second transaction
   * - `locktime` must be smaller than current timestamp (rule of Bitcoin)
   * - `locktime` must be greater than `expireTs` (rule of HTLC if enter the ELSE branch)
   */
  const tx2 = new bitcoin.Transaction()
  tx2.locktime = bip65.encode({ utc: utcNow() - 5400 })   // [BUG/TODO] If <3000 it's not ok
  tx2.addInput(Buffer.from(txid1, 'hex').reverse(), 0, 0xfffffffe)
  tx2.addOutput(bitcoin.address.toOutputScript(aliceAddress, network), lockAmount - 300)

  const hashType = bitcoin.Transaction.SIGHASH_ALL
  const signatureHash = tx2.hashForSignature(0, redeemScript, hashType)
  const aliceSignature = bitcoin.script.signature.encode(
    alice.sign(signatureHash), hashType,
  )
  const bobSignature = bitcoin.script.signature.encode(
    bob.sign(signatureHash), hashType,
  )

  const redeemScriptSig = bitcoin.payments.p2sh({
    redeem: {
      input: getInputScriptBob(secret, bob.publicKey, bobSignature),
      // input: getInputScriptAlice(alice.publicKey, aliceSignature),
      output: redeemScript,
    },
  }).input
  tx2.setInputScript(0, redeemScriptSig)
  const txHex2 = tx2.toHex()
  console.log("\nConstruct the second transaction:", txHex2)

  // Send the second transaction
  url = `${signetBaseUrl}/tx`
  response = await axios.post(url, txHex2, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })
  console.log("\nTx-2 hash: ", response.data)
  const txid2 = response.data
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid2}`)

  console.log("\nFinished!")
}

main()
