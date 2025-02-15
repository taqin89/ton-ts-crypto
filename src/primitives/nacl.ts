/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Port of TweetNaCl / NaCl to JavaScript for modern browsers and Node.js. Public domain.
// TweetNaCl.js 是一个高效、简洁且易于使用的加密库，专门用于实现现代加密算法。
// 它是 NaCl (Networking and Cryptography library) 的 JavaScript 实现，
// 旨在提供安全的加密原语，以支持端对端加密通信、身份验证等应用。
// TweetNaCl.js 的特点是小巧（只有几千行代码）且优化性能，适用于 Web 和 Node.js 环境。
// Tweet：这个前缀是为了强调 “小巧” 和 “快速”。
import nacl from 'tweetnacl';

export type KeyPair = {
    publicKey: Buffer;
    secretKey: Buffer;
}

export function keyPairFromSecretKey(secretKey: Buffer): KeyPair {
    let res = nacl.sign.keyPair.fromSecretKey(new Uint8Array(secretKey));

    return {
        publicKey: Buffer.from(res.publicKey),
        secretKey: Buffer.from(res.secretKey),
    }
}

export function keyPairFromSeed(secretKey: Buffer): KeyPair {
    let res = nacl.sign.keyPair.fromSeed(new Uint8Array(secretKey));

    return {
        publicKey: Buffer.from(res.publicKey),
        secretKey: Buffer.from(res.secretKey),
    }
}

export function sign(data: Buffer, secretKey: Buffer) {
    return Buffer.from(nacl.sign.detached(new Uint8Array(data), new Uint8Array(secretKey)));
}

export function signVerify(data: Buffer, signature: Buffer, publicKey: Buffer) {
    return nacl.sign.detached.verify(new Uint8Array(data), new Uint8Array(signature), new Uint8Array(publicKey));
}

export function sealBox(data: Buffer, nonce: Buffer, key: Buffer) {
    return Buffer.from(nacl.secretbox(data, nonce, key));
}

export function openBox(data: Buffer, nonce: Buffer, key: Buffer) {
    let res = nacl.secretbox.open(data, nonce, key);
    if (!res) {
        return null;
    }
    return Buffer.from(res);
}