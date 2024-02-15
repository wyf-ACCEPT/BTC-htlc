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

function getScriptInputRelease(userPubkey, userSignature) {
  return bitcoin.script.fromASM(
    `
    ${userSignature.toString('hex')}
    ${userPubkey.toString('hex')}
    OP_TRUE
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function getScriptInputCancel(lpPubkey, lpSignature) {
  return bitcoin.script.fromASM(
    `
    ${lpSignature.toString('hex')}
    ${lpPubkey.toString('hex')}
    OP_FALSE
    `
      .trim()
      .replace(/\s+/g, ' '),
  )
}

function getFinalizeRelease(redeemScript, userPubkey) {
  function getFinalizeReleaseInternal(inputIndex, input, script) {
    const decompiled = bitcoin.script.decompile(script)
    if (!decompiled || decompiled[0] !== bitcoin.opcodes.OP_IF) {
      throw new Error(`Can not finalize input #${inputIndex}`)
    }
    const payment = bitcoin.payments.p2sh({
      redeem: {
        input: getScriptInputRelease(
          userPubkey, input.partialSig[0].signature
        ),
        output: redeemScript
      }
    })
    return { finalScriptSig: payment.input }
  }
  return getFinalizeReleaseInternal
}

function getFinalizeCancelRelease(redeemScript, lpPubkey) {
  function getFinalizeCancelReleaseInternal(inputIndex, input, script){
    const decompiled = bitcoin.script.decompile(script)
    if (!decompiled || decompiled[0] !== bitcoin.opcodes.OP_IF) {
      throw new Error(`Can not finalize input #${inputIndex}`)
    }
    const payment = bitcoin.payments.p2sh({
      redeem: {
        input: getScriptInputCancel(
          lpPubkey, input.partialSig[0].signature
        ),
        output: redeemScript
      }
    })
    return { finalScriptSig: payment.input }
  }
  return getFinalizeCancelReleaseInternal
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

  // Use faucet to get some tBTC
  // See https://signet.bc-2.jp/ 

  /**
   * First transaction: Announce the script and calculate the script hash (P2SH address).
   * The script can be unlock by the following methods:
   * - User unlock before `expireTs` using LP's signature and User's signature
   * - Or LP unlock after `expireTs` using LP's signature
   */
  const lockAmount = 2000
  const expireTs = bip65.encode({ utc: utcNow() - 3600 * 2 })
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

  psbt1.signInput(0, lp)
  psbt1.validateSignaturesOfInput(0, validator)
  psbt1.finalizeAllInputs()

  const txid1 = await broadcastTransaction(psbt1)


  // Construct the second transaction
  // See https://bitcoinjs-guide.bitcoin-studio.com/bitcoinjs-guide/v5/part-three-pay-to-script-hash/timelocks/cltv_p2sh
  const psbt2 = new bitcoin.Psbt({ network })
  psbt2.addInput({
    hash: txid1,
    index: 0,
    sequence: 0xfffffffe,
    nonWitnessUtxo: Buffer.from(psbt1.extractTransaction().toHex(), 'hex'),
    redeemScript: Buffer.from(redeemScript, 'hex')
  })

  const releaseToUser = true

  if(releaseToUser) {
    psbt2.addOutput({
      address: userAddress,
      value: 1200,
    })
    psbt2.signInput(0, user)
    psbt2.finalizeInput(0, getFinalizeRelease(redeemScript, user.publicKey))
  } 
  else {
    psbt2.addOutput({
      address: lpAddress,
      value: 1200,
    })
    psbt2.setLocktime(utcNow() - 3600)
    psbt2.signInput(0, lp)
    psbt2.finalizeInput(0, getFinalizeCancelRelease(redeemScript, lp.publicKey))
  }

  await broadcastTransaction(psbt2)

  console.log("\nFinished!")
}

main()

