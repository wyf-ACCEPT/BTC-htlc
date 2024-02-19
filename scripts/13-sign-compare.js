const axios = require('axios')
const bip65 = require('bip65')
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
const { Wallet, ethers } = require('ethers')
require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet
const signetBaseUrl = "https://mempool.space/signet/api"
const validator = (pubkey, msghash, signature,) =>
  ECPair.fromPublicKey(pubkey).verify(msghash, signature)

function utcNow() {
  return Math.floor(Date.now() / 1000);
}

function getScriptOutputLock(
  encodedSwapHex, expireTs, lpAddressHex, userAddressHex
) {
  return bitcoin.script.fromASM(
    `
    OP_IF
      ${encodedSwapHex}
        OP_DROP
      OP_DUP
        OP_HASH160
        ${userAddressHex}
          OP_EQUALVERIFY
      OP_CHECKSIG
    OP_ELSE
      ${bitcoin.script.number.encode(expireTs).toString('hex')}
        OP_CHECKLOCKTIMEVERIFY
        OP_DROP
      OP_DUP
        OP_HASH160
        ${lpAddressHex}
          OP_EQUALVERIFY
      OP_CHECKSIG
    OP_ENDIF
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

async function broadcastTransaction(psbt) {
  const txHex = psbt.extractTransaction().toHex()
  console.log("\nConstructed the transaction:", txHex)
  const broadcastUrl = `${signetBaseUrl}/tx`
  const response = await axios.post(broadcastUrl, txHex, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })
  const txid = response.data
  console.log("\nTransaction hash: ", txid)
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid}`)
  return txid
}


async function main() {
  // Load wallet
  const pkWIF1 = process.env.PK_TEST
  const pkWIF2 = process.env.PK_TEST2
  const lp = ECPair.fromWIF(pkWIF1, network)
  const user = ECPair.fromWIF(pkWIF2, network)

  const { address: lpAddress } = bitcoin.payments.p2pkh({
    pubkey: lp.publicKey, network
  })
  const lpAddressHex = bitcoin.address
    .fromBase58Check(lpAddress, network).hash.toString('hex')
  const { address: userAddress } = bitcoin.payments.p2pkh({
    pubkey: user.publicKey, network
  })
  const userAddressHex = bitcoin.address
    .fromBase58Check(userAddress, network).hash.toString('hex')

  console.log("LP's P2PKH address: ", lpAddress)
  console.log("LP's P2PKH address (hex): ", lpAddressHex)
  console.log("User's P2PKH address: ", userAddress)
  console.log("User's P2PKH address (hex): ", userAddressHex)

  // Send some bitcoin to the P2SH's address
  const lockAmount = 2000
  const expireTs = bip65.encode({ utc: utcNow() - 3600 * 3 })
  const encodedSwapHex = "0100350c5280c400a97422bb2acd672000000dbba00065c2326168680f03c602"
  const redeemScript = getScriptOutputLock(
    encodedSwapHex, expireTs, lpAddressHex, userAddressHex
  )
  const { address: redeemScriptAddress } = bitcoin.payments.p2sh({
    redeem: { output: redeemScript, network }, network,
  })
  console.log("\nThe P2SH address:", redeemScriptAddress)

  // Get UTXOs
  let url, response, data
  url = `${signetBaseUrl}/address/${lpAddress}/utxo`
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
    address: redeemScriptAddress,
    value: lockAmount,
  })
  psbt1.addOutput({
    address: lpAddress,
    value: utxo0.value - lockAmount - 300
  })


  /**
   * Use unisat to sign, and validate in ethers.
   */

  // 1. Sign the transaction via unisat or bitcoinjs
  const inputIndex = 0
  psbt1.signInput(inputIndex, lp)
  const signatureBtcRaw = psbt1.data.inputs[inputIndex].partialSig[0].signature
  console.log(`\nSignature from bitcoinjs (length = ${signatureBtcRaw.length}): `, 
    signatureBtcRaw.toString('hex'))
  const flag = signatureBtcRaw.length == 72 ? 1 : 0
  const signatureBtcRawOffset = signatureBtcRaw.toString('hex').slice(8 + flag * 2)
  const signatureBtc = {
    r: '0x' + signatureBtcRawOffset.slice(0, 64),
    s: '0x' + signatureBtcRawOffset.slice(68, 132),
    // yParity: signatureBtcRaw.toString('hex').slice(140, 142) == '01' ? 1 : 0,
    // v: 27 + signatureBtcRaw.toString('hex').slice(140, 142) == '01' ? 1 : 0,
    serialized: '0x' + signatureBtcRawOffset.slice(0, 64) + signatureBtcRawOffset.slice(68, 132) + '1c',  // what about v?
  }

  // 2. Obtain the transaction hash
  const _unsignedTx = psbt1.data.globalMap.unsignedTx.tx
  const _prevoutIndex = _unsignedTx.ins[inputIndex].index
  const txHash = _unsignedTx.hashForSignature(
    inputIndex, 
    bitcoin.Transaction.fromBuffer(psbt1.data.inputs[inputIndex].nonWitnessUtxo)
      .outs[_prevoutIndex].script, 
    bitcoin.Transaction.SIGHASH_ALL,
  )
  console.log("Transaction hash to sign: ", txHash.toString('hex'))
  
  // 3. Sign the transaction via ethers
  const lpEthers = new Wallet(lp.privateKey.toString('hex'))
  const signatureEthers = lpEthers.signingKey.sign(txHash)

  console.log("r value is equal: ", signatureBtc.r == signatureEthers.r)
  console.log("s value is equal: ", signatureBtc.s == signatureEthers.s)
  // console.log("bitcoin sig length   : ", flag)
  // console.log("ethers  yParity      : ", signatureEthers.yParity)
  // console.log("bitcoin last 1 bytes : ", signatureBtcRaw.toString('hex').slice(-2))

  // 4. Verify the signature via ethers
  console.log("Recovered address: ", ethers.recoverAddress(txHash, signatureBtc.serialized))
  console.log("Original  address: ", lpEthers.address)

  // 5. Verify the signature via solidity
  // @openzeppelin: ECDSA.recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)

  // 6. Verify the signature via bitcoin script
  // See the user journey in ./12-unisat.js

  
  psbt1.validateSignaturesOfInput(0, validator)
  psbt1.finalizeAllInputs()

  /**
   * hash:   1dd2c6e729e1b669d5a3adf124edf050b9a8903b499fcd1bbb288b7b93c2d36b
   * sig:    bc550c8805bce4a581319f85e442e11841485800b0ada9421c0ce55e62e8cd35
   *         019a2373dad527595e99d8727d44e49fe728e92d71e0ecbae42d34cc605257b7
   * lp-pk:  f04b9a36c97c42064fdd0ad9c5bcc364f7efe4cb1d0ca008ad41e6fa03fee072
   * lp-pub: 02 54393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10
   * 
   * 30 44 02 20 7368b42b0a6715ab9380d01475744cd041e37a90cf6817091c22a0a7cb19fd7f
   *       02 20 3e117cf1bf89d30942ca523b040d46b279133d64c6fc06bedfb110bacf7b4886 01
   * 30 45 02 21 00
   */


}

main()
