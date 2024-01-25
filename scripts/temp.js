const bitcoin = require('bitcoinjs-lib');
const { Psbt } = bitcoin;
const { sha256 } = bitcoin.crypto;

// 网络参数
const network = bitcoin.networks.bitcoin; // 对于测试网使用 bitcoin.networks.testnet

// Alice 的钱包信息
const alicePrivateKey = '你的私钥';
// const aliceKeyPair = bitcoin.ECPair.fromWIF(alicePrivateKey, network);

// 创建哈希锁定脚本
const secret = Buffer.from('hi'); // Alice 选择的秘密
const hash = sha256(secret);
const hashLockScript = bitcoin.script.compile([
  bitcoin.opcodes.OP_SHA256,
  hash,
  bitcoin.opcodes.OP_EQUAL,
]);

// 创建 P2SH 地址
const p2sh = bitcoin.payments.p2sh({
  redeem: { output: hashLockScript, network },
  network,
});
const p2shAddress = p2sh.address;

// 构建交易
const psbt = new Psbt({ network });
psbt.addInput({
  // 前一个交易的相关信息
  hash: '前一个交易的哈希',
  index: 0, // 前一个交易中的输出索引
  nonWitnessUtxo: Buffer.from('前一个交易的原始数据', 'hex'),
});
psbt.addOutput({
  address: p2shAddress, // 发送到 P2SH 地址
  value: 1000, // 发送金额（单位：聪）
});
// Alice 签名
psbt.signInput(0, aliceKeyPair);
psbt.validateSignaturesOfInput(0);
psbt.finalizeAllInputs();

// 获得原始交易数据（十六进制）
const txHex = psbt.extractTransaction().toHex();

// 广播交易（这部分需要使用比特币客户端或者第三方API）
console.log(txHex);
