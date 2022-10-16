let { bech32, bech32m } = require('bech32');
let { bs58Decode, bs58Encode } = require('crypto-addr-codec');

// const { prefix, words } = bech32.decode('df1q4tc5anw0gckga9738954f5segtue3rkwn7ahxp');

// console.log(prefix);
// console.log(words);

// const script = bech32.fromWords(words.slice(1));
// let decodingVersion = words[0];
// if (decodingVersion > 0) {
//   decodingVersion += 0x50;
// }

// console.log('decodingVersion is: ' + decodingVersion);

// let buffer = Buffer.concat([Buffer.from([decodingVersion, script.length]), Buffer.from(script)]);
// console.log(buffer);

// let encodingVersion = buffer.readUInt8(0);
// if (encodingVersion >= 0x51 && encodingVersion <= 0x60) {
//   encodingVersion -= 0x50;
// } else if (encodingVersion !== 0x00) {
//   throw Error('Unrecognised address format');
// }

// const endodedWords = [encodingVersion].concat(bech32.toWords(buffer.slice(2, buffer.readUInt8(1) + 2)));
// console.log(bech32.encode('df', endodedWords));

function makeBitcoinBase58CheckEncoder(data) {
  switch (data.readUInt8(0)) {
    case 0x76: // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
      if (
        data.readUInt8(1) !== 0xa9 ||
        data.readUInt8(data.length - 2) !== 0x88 ||
        data.readUInt8(data.length - 1) !== 0xac
      ) {
        throw Error('Unrecognised address format');
      }
      addr = Buffer.concat([Buffer.from([0x90]), data.slice(2, 2 + data.readUInt8(2))]);
      // @ts-ignore
      return bs58Encode(addr);
    case 0xa9: // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
      if (data.readUInt8(data.length - 1) !== 0x87) {
        throw Error('Unrecognised address format');
      }
      addr = Buffer.concat([Buffer.from([0x90]), data.slice(2, 2 + data.readUInt8(1))]);
      return bs58Encode(addr);
    default:
      throw Error('Unrecognised address format');
  }
}

const originalAddress = bs58Decode('dHmPhTMnnFg2jf1Esy4813kFCpWP6EtzeD');
let p2pkhVersions = [0x90];

let buffer = Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),
  originalAddress.slice(p2pkhVersions[0].length),
  Buffer.from([0x88, 0xac]),
]);

console.log('decoded address to HEX:');
console.log(buffer);

console.log('Re-Encoded Address:');

console.log(makeBitcoinBase58CheckEncoder(buffer));
