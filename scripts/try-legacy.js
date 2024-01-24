const axios = require('axios');
const bitcoin = require('bitcoinjs-lib')
const bs58 = require('bs58')
const { ECPairFactory } = require('ecpair')
require('dotenv').config()

const tinysecp = require('tiny-secp256k1')
bitcoin.initEccLib(tinysecp)
const ECPair = ECPairFactory(tinysecp)
const network = bitcoin.networks.testnet

const validator = (
  pubkey,
  msghash,
  signature,
) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);


async function main() {
  // Create wallet
  const pkWIF = process.env.PK_TEST
  const keypair = ECPair.fromWIF(pkWIF, network)

  const { address } = bitcoin.payments.p2pkh({ 
    pubkey: keypair.publicKey, network
  })
  console.log(address)

  const psbt = new bitcoin.Psbt({ network: network })

  psbt.addInput({
    hash: '7036df7cee49502b26fa6f8992335a0f15ddaabfde308ef61f06cfcb1d35f821',
    index: 0,
    nonWitnessUtxo: Buffer.from(
      // See https://mempool.space/signet/tx/7036df7cee49502b26fa6f8992335a0f15ddaabfde308ef61f06cfcb1d35f821
      // ???
      '02000000000101c4fea553fc3f22075a369404f948bfcc46fbafeebe010d4c12c89c4d384d38150000000000feffffff02' + 
      // value in satoshis (Int64LE) = 0x0186a0 = 100000
      'a086010000000000' + 
      // scriptPubkey 1 length
      '19' + 
      // scriptPubkey 1
      '76a914ce90de3517b68084878655f3c5b3f2f4c24840ca88ac' + 
      // value in satoshis (Int64LE) = 0x0654b91e75db = 6960952800731
      'db751eb954060000' + 
      // scriptPubkey 2 length
      '16' + 
      // scriptPubkey 2
      '0014777913fb5808f263329484873cf4388f09878525' + 
      // ???
      '0247304402201ef434cfa1e014546c92e7097484d64bfed75d2f0092c9991370d2f2e2cf2f7402203e42e87b7e4c7ec2458c5c4f3d7559af0975433fd05eac5db370add4ef7f7a680121038d60413a2b5415fc0419edb65c02ac59199f1036793fb3e8d2a617b6c5bf8d4d94bc0200', 'hex'
    )
  })
  psbt.addOutput({
    address: 'mzMB3BAQBdYogbPcMP53KLPki4myJ6zV96',
    value: 5000,
  })
  psbt.signInput(0, keypair)
  psbt.validateSignaturesOfInput(0, validator)

  psbt.finalizeAllInputs()    
    // finalize 后才能得到交易的 hex，调用 `psbt.extractTransaction().toHex()` 即可得到。
    // 如果使用 taproot 格式地址，目前还没办法 finalize，会报错。原因暂时未知。

  console.log(psbt.extractTransaction().toHex())
  console.log("Finish finalize!")

  // psbt.extractTransaction().toHex() -> '020000000121f8351dcbcf061ff68e30debfaadd150f5a3392896ffa262b5049ee7cdf3670000000006b483045022100b483aacc0ada749717401b890b318620eac7439f5b903d4307b23ba1746249da0220297a0c92cbe55c36bdcd2d8d8de320cef7b324a90247e26cc0a3b7a3efcab46301210254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10ffffffff016400000000000000160014777913fb5808f263329484873cf4388f0987852500000000'
  '02000000' +              // version
  '01' +                    // number of input
  '21f8351dcbcf061ff68e30debfaadd150f5a3392896ffa262b5049ee7cdf3670' +
                            // previous hash (little endian!)
  '00000000' +              // output number in previous tx
  '6b' +                    // size of signature script (0x6b * 2 = 214)
  '483045022100b483aacc0ada749717401b890b318620eac7439f5b903d4307b23ba1746249da0220297a0c92cbe55c36bdcd2d8d8de320cef7b324a90247e26cc0a3b7a3efcab46301210254393167303dfc20d60d60d3ec55873f3bb01823da7a072a02cfc1697ef4ed10' +  // signature script
  'ffffffff' +              // sequence number
  '01' +                    // number of output
  '6400000000000000' +      // amount (0x64 = 100)
  '16' +                    // size of script 1 (0x16 * 2 = 44)
  '0014777913fb5808f263329484873cf4388f09878525' +    // script 1
  '00000000'                // lock time

}

main()
