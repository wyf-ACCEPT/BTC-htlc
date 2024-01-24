const axios = require('axios');
const bitcoin = require('bitcoinjs-lib')
const bs58 = require('bs58')
const { ECPairFactory } = require('ecpair')
require('dotenv').config()

const tinysecp = require('tiny-secp256k1')
bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet

function tapTweakHash(pubKey, h) {
  return bitcoin.crypto.taggedHash(
    'TapTweak',
    Buffer.concat(h ? [pubKey, h] : [pubKey]),
  )
}

function toXOnly(pubkey) {
  return pubkey.subarray(1, 33)
}

function tweakSigner(signer, opts) {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  let privateKey = signer.privateKey
  if (!privateKey) {
    throw new Error('Private key is required for tweaking signer!');
  }
  if (signer.publicKey[0] === 3) {
    privateKey = tinysecp.privateNegate(privateKey);
  }

  const tweakedPrivateKey = tinysecp.privateAdd(
    privateKey,
    tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
  )
  if (!tweakedPrivateKey) {
    throw new Error('Invalid tweaked private key!')
  }

  return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
    network: opts.network,
  })
}

const validator = (
  pubkey,
  msghash,
  signature,
) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);


async function main() {
  // Create taproot wallet 
  // See https://github.com/Eunovo/taproot-with-bitcoinjs/blob/main/src/index.ts
  const pkWIF = process.env.PK_TEST
  const keypair = ECPair.fromWIF(pkWIF, network)
  const tweakedSigner = tweakSigner(keypair, { network })

  const { address } = bitcoin.payments.p2tr({ 
    pubkey: toXOnly(tweakedSigner.publicKey), network
  })
  console.log(address)    // Same as Unisat wallet!

  const psbt = new bitcoin.Psbt({ network: network })
  // psbt.opts = { network: network }

  // // const base_url = 'https://mempool.space/signet/api'
  // const base_url = 'https://api.blockcypher.com/v1/btc/test3'
  // console.log(`${base_url}/addrs/${address}?unspentOnly=true`)

  // const utxos = await axios.get(
  //   `${base_url}/addrs/tb1qg73ddcpg6nmsel2fvpa43klcjrnve7rgkrc0c4?unspentOnly=true`
  // )
  // const tx_data=await axios.get(
  //   `${base_url}/txs/983cca09b629959cc163c98bddca9f430fbe8a38fc1287822402aa187c92d9f9?includeHex=true`
  // )

  // console.log(typeof(utxos), typeof(tx_data))

  // const utxo = utxos.data.txrefs[0]
  // utxo.hex = tx_data.data.hex

  psbt.addInput({
    hash: '0935e21a66060cd0478d0052437c642dcac273a323e296789fa93806a62ae8fb',
    index: 1,
    nonWitnessUtxo: Buffer.from(
      '01000000000101511a07671514ba3193740a0b0cdf602a8f02b9996100ee4edc23c512f6da7bc30100000000f5ffffff02' +
      // value in satoshis (Int64LE) = 0x0812 = 2066
      '1208000000000000' + 
      // scriptPubkey 1 length
      '22' + 
      // scriptPubkey 1
      '5120100a701adf70b9c84cf7735ad6425f48251a9a1d7bca127986dc03112a1a2392' + 
      // value in satoshis (Int64LE) = 0x15ca74 = 1428084
      '74ca150000000000' + 
      // scriptPubkey 2 length
      '22' + 
      // scriptPubkey 2
      '51202439d09a4f32f68063ca7ad812c3069c4d22c554c3ff365f8b4a94c100e2bf2f' + 
      // ???
      '01404b18d935836b807d322555fd54e8a1aa4cc1110b816cc4fd1e37f7f81e111c77abbc80c967b9ed8b6ee0b191835158b89d9955b396f5a167f6024e7a0028b30200000000', 'hex'
    )
  })
  psbt.addOutput({
    address: 'tb1pzq98qxklwzuusn8hwdddvsjlfqj34xsa009py7vxmsp3z2s6ywfqmupjh2',
    value: 100,
  })
  psbt.signInput(0, tweakedSigner)
  psbt.validateSignaturesOfInput(0, validator)
  psbt.finalizeAllInputs()
}

main()
