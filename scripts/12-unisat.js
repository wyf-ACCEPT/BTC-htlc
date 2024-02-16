const axios = require('axios')
const bip65 = require('bip65')
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const readlineSync = require('readline-sync');
const { readFileSync } = require('fs')
const { ECPairFactory } = require('ecpair')
require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet
const signetBaseUrl = "https://mempool.space/signet/api"
const testnetBaseUrl = "https://mempool.space/testnet/api"
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
  function getFinalizeCancelReleaseInternal(inputIndex, input, script) {
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
  const broadcastUrl = `${testnetBaseUrl}/tx`
  const response = await axios.post(broadcastUrl, txHex, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })
  const txid = response.data
  console.log("\nTransaction hash: ", txid)
  console.log("View on the explorer: ", `https://mempool.space/testnet/tx/${txid}`)
  return txid
}


async function main() {
  /**
   * Load wallet and variables
   */
  const lpAddress = 'mghW6tWaqMmHsy6C4G9TQgHhqZmTm2SFJ7'
  const userAddress = 'mnGQjw43aNvrA18wsBcPJqiCEibHiQ6awx'
  const userPubkeyHex = '03d30a4872dfa2151a59d412a45dff1445d2e11441974472735786418eafe2942d'

  const lpAddressHex = bitcoin.address
    .fromBase58Check(lpAddress, network).hash.toString('hex')
  const userAddressHex = bitcoin.address
    .fromBase58Check(userAddress, network).hash.toString('hex')

  console.log("LP's P2PKH address: ", lpAddress)
  console.log("LP's P2PKH address (hex): ", lpAddressHex)
  console.log("User's P2PKH address: ", userAddress)
  console.log("User's P2PKH address (hex): ", userAddressHex)

  /**
   * Construct the redeem script
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

  /**
   * Send bitcoin to the P2SH address (in unisat)
   */
  console.log(
    "\nPaste this code snippet into Chrome:",
    `\n\x1b[32mawait unisat.sendBitcoin("${redeemScriptAddress}", ${lockAmount})\x1b[0m`
  )

  const txid1 = readlineSync.question('\nInput your txid (from Chrome): ')
  const nonWitnessUtxo1 = await (await fetch(`${testnetBaseUrl}/tx/${txid1}/hex`)).text()
  console.log("\nThe hex string of this txid1:", nonWitnessUtxo1)

  /**
   * Construct the second transaction
   */
  const psbt2 = new bitcoin.Psbt({ network })
  psbt2.addInput({
    hash: txid1,
    index: 0,
    sequence: 0xfffffffe,
    nonWitnessUtxo: Buffer.from(nonWitnessUtxo1, 'hex'),
    redeemScript: Buffer.from(redeemScript, 'hex')
  })

  const releaseToUser = true

  if (releaseToUser) {
    psbt2.addOutput({
      address: userAddress,
      value: 1200,
    })

    console.log(
      "\nPaste this code snippet into Chrome:",
      `\n\x1b[32mawait unisat.signPsbt("${psbt2.toHex()}", { autoFinalized: false, toSignInputs: [{ index: 0, address: "${userAddress}" }]})` +
      `\x1b[0m`
    )
    readlineSync.question('\nPaste your signed psbt (from Chrome) to `../hexstring/psbt-hexstring.txt`. Press Enter to continue...')

    const psbt2signedHex = readFileSync('./hexstring/psbt-hexstring.txt', 'utf8')
    const psbt2signed = bitcoin.Psbt.fromHex(psbt2signedHex)
    psbt2signed.finalizeInput(0, getFinalizeRelease(redeemScript, Buffer.from(userPubkeyHex, 'hex')))
    await broadcastTransaction(psbt2signed)

  }
  else {
    psbt2.addOutput({
      address: lpAddress,
      value: 1200,
    })
    psbt2.setLocktime(utcNow() - 3600)
    psbt2.signInput(0, lp)
    psbt2.finalizeInput(0, getFinalizeCancelRelease(redeemScript, lp.publicKey))
    await broadcastTransaction(psbt2)
  }

  console.log("\nFinished!")
}

main()

