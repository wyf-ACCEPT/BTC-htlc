const axios = require('axios')
const bip65 = require('bip65')
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
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
  encodedSwapHex, expireTs, aliceP2pkhAddressHex, bobP2pkhAddressHex
) {
  return bitcoin.script.fromASM(
    `
    OP_IF
      ${encodedSwapHex}
      OP_DROP
      OP_DUP
        OP_HASH160
        ${bobP2pkhAddressHex}
          OP_EQUALVERIFY
      OP_CHECKSIGVERIFY
    OP_ELSE
      ${bitcoin.script.number.encode(expireTs).toString('hex')}
        OP_CHECKLOCKTIMEVERIFY
        OP_DROP
    OP_ENDIF
    OP_DUP
      OP_HASH160
      ${aliceP2pkhAddressHex}
        OP_EQUALVERIFY
    OP_CHECKSIG
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function getInputScriptBob(alicePubkey, aliceSignature, bobPubkey, bobSignature) {
  return bitcoin.script.fromASM(
    `
    ${aliceSignature.toString('hex')}
    ${alicePubkey.toString('hex')}
    ${bobSignature.toString('hex')}
    ${bobPubkey.toString('hex')}
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
  const aliceP2pkhAddressHex = bitcoin.address
    .fromBase58Check(aliceAddress, network).hash.toString('hex')
  const { address: bobAddress } = bitcoin.payments.p2pkh({
    pubkey: bob.publicKey, network
  })
  const bobP2pkhAddressHex = bitcoin.address
    .fromBase58Check(bobAddress, network).hash.toString('hex')

  console.log("Alice's address: ", aliceAddress)
  console.log("Alice's address (hex): ", aliceP2pkhAddressHex)
  console.log("Bob's address: ", bobAddress)
  console.log("Bob's address (hex): ", bobP2pkhAddressHex)

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  /**
   * First transaction 
   * - Bob unlock before `expireTs` using Alice's signature and Bob's signature
   * - Or Alice unlock after `expireTs` using Alice's signature
   */
  const lockAmount = 2000
  const expireTs = bip65.encode({ utc: utcNow() - 3600 * 2 })
  const encodedSwapHex = "0100350c5280c400a97422bb2acd672000000dbba00065c2326168680f03c602"
  const redeemScript = getOutputScript(
    encodedSwapHex, expireTs, aliceP2pkhAddressHex, bobP2pkhAddressHex
  )
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

  // Construct the second transaction
  const tx2 = new bitcoin.Transaction()
  tx2.addInput(Buffer.from(txid1, 'hex').reverse(), 0, 0xfffffffe)
  const hashType = bitcoin.Transaction.SIGHASH_ALL
  let inputScript

  // Choose to release the fund to Bob or Alice
  const releaseToBob = false

  if (releaseToBob) {
    tx2.addOutput(bitcoin.address.toOutputScript(bobAddress, network), lockAmount - 500)

    const signatureHash = tx2.hashForSignature(0, redeemScript, hashType)
    const aliceSignature = bitcoin.script.signature.encode(
      alice.sign(signatureHash), hashType,
    )
    const bobSignature = bitcoin.script.signature.encode(
      bob.sign(signatureHash), hashType,
    )
    inputScript = getInputScriptBob(alice.publicKey, aliceSignature, bob.publicKey, bobSignature)
  }
  else {
    /**
     * If it's Alice's turn, she can unlock the fund, while:
     * - `locktime` must be smaller than current timestamp (rule of Bitcoin)
     * - `locktime` must be greater than `expireTs` (rule of HTLC if enter the ELSE branch)
     */
    tx2.locktime = bip65.encode({ utc: utcNow() - 3600 })   // [BUG/TODO] If <3000 it's not ok
    tx2.addOutput(bitcoin.address.toOutputScript(aliceAddress, network), lockAmount - 500)

    const signatureHash = tx2.hashForSignature(0, redeemScript, hashType)
    const aliceSignature = bitcoin.script.signature.encode(
      alice.sign(signatureHash), hashType,
    )
    inputScript = getInputScriptAlice(alice.publicKey, aliceSignature)
  }

  // Continue to construct the second transaction
  const redeemScriptSig = bitcoin.payments.p2sh({
    redeem: {
      input: inputScript,
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


// Example transaction hex string. See:
//  https://dev.to/thunderbiscuit/deconstructing-a-bitcoin-transaction-4l2n
/**
 * 01000000
 * 01
 * 35c0c6c325588305c8801a0c355ba6af12d2ff0c0038a626ac019df03bfe4dea
 * 00000000
 * cb
 *  47
 *    304402200320560bd131ec03d0535708e06bab67ea5b61d70131e0c1982cf560dca2fb \
 *    d7022020979d995a3496cf64f15cd282c6974a8c578f546536abffe5ba4567f9de7be801
 *  21
 *    0254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10
 *  00
 *  4c
 *  5e
 *    63
 *    20
 *      0100350c5280c400a97422bb2acd672000000dbba00065c2326168680f03c602
 *    75 76 a9 14 002483c2041ccb861a40e12346d3c2478b4aecce \
 *    88 ad 67 04 9801c265 b1 75 68 76 a9 14 ce90de3517b68084878655f3c5b3f2f4c24840ca 88 ac
 * feffffff
 * 01
 * dc050000000000001976a914ce90de3517b68084878655f3c5b3f2f4c24840ca88acab0fc265
 */



// Example psbt hex string.
/**
 * 70736274ff01005e0200000001d91f55430b405b587f1df5904d45363f521042991e2de9d9aff976160c19e2230000000000
 * ffffffff
 * 01
 * 42d8130000000000 (1300546)
 * 22
 * 51204453feea163965199ab596212f0d9f843c4fa98a223d8c23df6005c9688ec8b2
 * 00000000
 * 000100fd4f01010000000001012420456ae84077b018ee0a058aa0450112e366a65af2b763dd49a9da2c15086c0100000000fdffffff0122020000000000002251204453feea163965199ab596212f0d9f843c4fa98a223d8c23df6005c9688ec8b20340b13027dcb04d7b87871dde7689a0e35b149f6425e051dacacc3e27c52f144998c3c7d28e104506cfde5cad3fd2f242c176b70e2f32f751f18ea77c8602955fbd8a20d2b683694c74571fcc79e4045dd326807601f43dfcc0a0fc551b674071d095cdac0063036f72640101116d6f64656c2f676c74662d62696e617279004b2f636f6e74656e742f3032373237343434666637333366383565323763363130623066383034313938633365313235316462396439303836356632323838663561633035363465396669306821c0d2b683694c74571fcc79e4045dd326807601f43dfcc0a0fc551b674071d095cd0000000001012b22020000000000002251204453feea163965199ab596212f0d9f843c4fa98a223d8c23df6005c9688ec8b201030483000000011720b1ef69d60392abac53478690ae6d6b12221338131e170f9b0d091c599df884a30000
 */


/**
 * 70736274ff0100750200000001c37238fbb5a289793669eb415df47c119c1c73ae99f6d939cf4cec0a170b71990100000000
 * []  ffffffff02d00700000000000017a9144e9dd560003348b8f13a9a9ca521240a052eff2a87
 * 88fd0b00000000001976a914ce90de3517b68084878655f3c5b3f2f4c24840ca88ac00000000
 * 000100df02000000012c64398681a266da9af119dbd5952f152f0a8a06223d558d697efc79447d31e1010000006a4730440220104810dbe72ccfa3ce7a9a1b3fdb668491f034dc25efce37fd673b5afc04c9de022070b8958c988159089d3256004d0f9eb0400e07fe6bbe761b3dadb4d728286ff801210254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10ffffffff02d00700000000000017a9141db52d63ff17d8aae333982d612f1775b16cfb3f8784060c00000000001976a914ce90de3517b68084878655f3c5b3f2f4c24840ca88ac000000000107
 * 6a4730440220211320401467446b842a603d3b3196f50d5862d41bb7ad3a22196dd20cf1cd60022064dc81f2e936499480e7cec26b0d0c8491f7b4d6086a84388df7f02c3d33666401210254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10
 * 000000
 * 
 * 
 * 0200000001c37238fbb5a289793669eb415df47c119c1c73ae99f6d939cf4cec0a170b719901000000
 * 6a4730440220211320401467446b842a603d3b3196f50d5862d41bb7ad3a22196dd20cf1cd60022064dc81f2e936499480e7cec26b0d0c8491f7b4d6086a84388df7f02c3d33666401210254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10
 * []  ffffffff02d00700000000000017a9144e9dd560003348b8f13a9a9ca521240a052eff2a87
 * 88fd0b00000000001976a914ce90de3517b68084878655f3c5b3f2f4c24840ca88ac00000000
 */