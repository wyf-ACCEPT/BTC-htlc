const bitcoin = require('bitcoinjs-lib')
const bip39 = require('bip39')
const { Wallet } = require('ethers')

async function main() {
  const w = Wallet.createRandom()
  console.log(w)
  let words = bip39.generateMnemonic(128)
  console.log(words)
}

main()
