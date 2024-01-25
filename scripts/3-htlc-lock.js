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

  // Construct a HTLC script
  const lockAmount = 2000
  const secret = Buffer.from('hi')
  const hash = sha256(secret)
  const hashLockScript = bitcoin.script.compile([
    bitcoin.opcodes.OP_SHA256,
    // hash,
    bitcoin.opcodes.OP_EQUAL,
    bitcoin.opcodes.OP_VERIFY,
  ])
  console.log("\nThe hash value of HTLC: ", '0x' + hash.toString('hex'))
  console.log("The HTLC script (hex) : ", '0x' + hashLockScript.toString('hex'))

  // Get the pay-to-script-hash address
  const p2sh = bitcoin.payments.p2sh({
    redeem: { output: hashLockScript, network },
    network,
  })
  const p2shAddress = p2sh.address
  console.log("\nThe P2SH address:", p2shAddress)

  // Get UTXOs
  let url, response, data
  url = `${signetBaseUrl}/address/${myAddress}/utxo`
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
    redeemScript: p2sh.redeem.output
  })
  psbt1.addOutput({
    address: p2shAddress,
    value: lockAmount,
  })
  psbt1.addOutput({
    address: myAddress,
    value: utxo0.value - lockAmount - 300
  })
  psbt1.signInput(0, myKeypair)
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
  console.log("\nNew tx hash: ", response.data)
  const txid1 = response.data
  console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid1}`)
  console.log("\nFinished!")

  // // Construct the second transaction
  // const psbt2 = new bitcoin.Psbt({ network })
  // psbt2.addInput({
  //   hash: txid1,
  //   index: 0, 
  //   witnessUtxo: {
  //     script: hashLockScript,
  //     value: lockAmount,
  //   },
  //   witnessScript: hashLockScript,
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

  // // Send the second transaction
  // url = `${signetBaseUrl}/tx`
  // response = await axios.post(url, txHex2, {
  //   headers: {
  //     'Content-Type': 'application/x-www-form-urlencoded',
  //   },
  // })
  // console.log("\nNew tx hash: ", response.data)
  // const txid2 = response.data
  // console.log("View on the explorer: ", `https://mempool.space/signet/tx/${txid2}`)
  // console.log("\nFinished!")
}

main()




function csvGetFinalScripts(
  inputIndex,
  input,
  script,
  isSegwit,
  isP2SH,
  isP2WSH,
) {
  // Step 1: Check to make sure the meaningful script matches what you expect.
  const decompiled = bitcoin.script.decompile(script);
  // Checking if first OP is OP_IF... should do better check in production!
  // You may even want to check the public keys in the script against a
  // whitelist depending on the circumstances!!!
  // You also want to check the contents of the input to see if you have enough
  // info to actually construct the scriptSig and Witnesses.
  if (!decompiled || decompiled[0] !== bitcoin.opcodes.OP_IF) {
    throw new Error(`Can not finalize input #${inputIndex}`);
  }

  // Step 2: Create final scripts
  let payment = {
    network: regtest,
    output: script,
    // This logic should be more strict and make sure the pubkeys in the
    // meaningful script are the ones signing in the PSBT etc.
    input: bitcoin.script.compile([
      input.partialSig[0].signature,
      bitcoin.opcodes.OP_TRUE,
    ]),
  };
  if (isP2WSH && isSegwit)
    payment = bitcoin.payments.p2wsh({
      network: regtest,
      redeem: payment,
    });
  if (isP2SH)
    payment = bitcoin.payments.p2sh({
      network: regtest,
      redeem: payment,
    });

  function witnessStackToScriptWitness(witness) {
    let buffer = Buffer.allocUnsafe(0);

    function writeSlice(slice) {
      buffer = Buffer.concat([buffer, Buffer.from(slice)]);
    }

    function writeVarInt(i) {
      const currentLen = buffer.length;
      const varintLen = varuint.encodingLength(i);

      buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
      varuint.encode(i, buffer, currentLen);
    }

    function writeVarSlice(slice) {
      writeVarInt(slice.length);
      writeSlice(slice);
    }

    function writeVector(vector) {
      writeVarInt(vector.length);
      vector.forEach(writeVarSlice);
    }

    writeVector(witness);

    return buffer;
  }

  return {
    finalScriptSig: payment.input,
    finalScriptWitness:
      payment.witness && payment.witness.length > 0
        ? witnessStackToScriptWitness(payment.witness)
        : undefined,
  };
}
