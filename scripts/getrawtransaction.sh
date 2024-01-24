BTC_RPC=https://tiniest-fittest-isle.btc.quiknode.pro/cd8be120bc67c39bd098a4104fefe4f6ab8f8a2d/

# curl $BTC_RPC -X POST -H "Content-Type: application/json" --data '{"method": "getrawtransaction", "params": ["10b54fd708ab2e5703979b4ba27ca0339882abc2062e77fbe51e625203a49642", 0]}'

curl $BTC_RPC \
    -X POST \
    -H "Content-Type: application/json" \
    --data '{"method": "decoderawtransaction", "params": ["02000000000101c4fea553fc3f22075a369404f948bfcc46fbafeebe010d4c12c89c4d384d38150000000000feffffff02a0860100000000001976a914ce90de3517b68084878655f3c5b3f2f4c24840ca88acdb751eb954060000160014777913fb5808f263329484873cf4388f098785250247304402201ef434cfa1e014546c92e7097484d64bfed75d2f0092c9991370d2f2e2cf2f7402203e42e87b7e4c7ec2458c5c4f3d7559af0975433fd05eac5db370add4ef7f7a680121038d60413a2b5415fc0419edb65c02ac59199f1036793fb3e8d2a617b6c5bf8d4d94bc0200"]}'


# curl -sSL "https://mempool.space/api/address/1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY/utxo"
curl -sSL "https://mempool.space/signet/api/address/mzMB3BAQBdYogbPcMP53KLPki4myJ6zV96/utxo"
curl -sSL "https://mempool.space/signet/api/tx/bb8f0481fec6884900af0d53893e396d643c529193e71ecf9901500d85cc66c7/hex"


# mempool request: https://mempool.space/zh/docs/api/rest#get-address-utxo
# signet faucet: https://signet.bc-2.jp/
# script wiki: https://en.bitcoin.it/wiki/Script
# deconstruct tx: https://dev.to/thunderbiscuit/deconstructing-a-bitcoin-transaction-4l2n
# mempool broadcast: https://mempool.space/signet/tx/push
# keypair generate: https://github.com/ObsidianLabs/Secrypto/blob/develop/packages/secrypto-wallet/src/lib/KeyPair.js#L122
# unisat sign: https://docs.unisat.io/dev/unisat-developer-service/unisat-wallet#signpsbt