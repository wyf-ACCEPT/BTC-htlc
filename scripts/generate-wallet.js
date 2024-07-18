const bitcoin = require('bitcoinjs-lib')
const bip39 = require('bip39')
const { Wallet } = require('ethers')

async function main() {
  const wallet = Wallet.createRandom()
  console.log(wallet)
  console.log(wallet.privateKey)
  let words = bip39.generateMnemonic(128)
  console.log(words)
}

main()
