const axios = require('axios');
const bitcoin = require('bitcoinjs-lib')
const tinysecp = require('tiny-secp256k1')
const { ECPairFactory } = require('ecpair')
const { toXOnly } = require('bitcoinjs-lib/src/psbt/bip371')
require('dotenv').config()

bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.bitcoin
const baseUrl = "https://mempool.space/api"

const validator = (
  pubkey,
  msghash,
  signature,
) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);


async function main() {
  const pkWIF = "L3jimhVXbV5XEfxoW4Ro4nparD2Eq3MfQKSpF7YgiRDX9w9pgdqu"
  const keypair = ECPair.fromWIF(pkWIF, network)
  const XOnlyPubkey = toXOnly(keypair.publicKey)
  const { address, output } = bitcoin.payments.p2tr({
    internalPubkey: XOnlyPubkey, network
  })
  console.log("Your address: ", address)

  const tweakedKeypair = keypair.tweak(
    bitcoin.crypto.taggedHash('TapTweak', XOnlyPubkey),
  )

  let url, response, data
  url = `${baseUrl}/address/${address}/utxo`
  response = await fetch(url)
  data = await response.json()
  let availableUtxos = data.filter(x => x.value > 0)
  if (availableUtxos.length == 0)
    throw new Error("No available UTXO!")

  const groupSize = 2
  const psbt = new bitcoin.Psbt({ network: network })
  let values = 0
  for (let i = 0; i < groupSize; i++) {
    const utxo = availableUtxos[i]
    console.log(`UTXO ${i}: ${utxo.txid}, ${utxo.value} sats.`)
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        script: output,
        value: utxo.value,
      },
      tapInternalKey: XOnlyPubkey,
    })
    values += utxo.value
  }

  const vbytes = 10.5 + 57.5 * groupSize + 43
  const gas = Math.ceil(vbytes * 3) + 5
  console.log("Total gas:", vbytes)
  console.log("Total value:", values)

  psbt.addOutput({
    address: address,
    value: values - gas,
  })
  psbt.signAllInputs(tweakedKeypair)
  psbt.finalizeAllInputs()
  let newTxHex = psbt.extractTransaction().toHex()
  console.log("\nConstruct the transaction:", newTxHex)

  url = `${baseUrl}/tx`
  response = await axios.post(url, newTxHex, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })
  console.log("\nNew tx hash: ", response.data);
  console.log("View on the explorer: ", `https://mempool.space/tx/${response.data}`)
  console.log("\nFinished!")
}

main()
