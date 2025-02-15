/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import jsSHA from 'jssha';
import { hmac_sha512 as internal } from '@ton/crypto-primitives';


// HMAC (Hash-based Message Authentication Code) 是一种基于哈希函数的消息认证码，用于验证消息的完整性和身份认证。
// 它使用一个共享的密钥和哈希函数（如 SHA-512）来生成一个固定长度的哈希值。HMAC 能够提供比普通哈希更强的安全性，防止消息在传输过程中被篡改。
// HMAC-SHA-512 是使用 SHA-512 哈希函数计算的 HMAC，通常用于数据验证和安全协议中。

export async function hmac_sha512_fallback(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    let keyBuffer: Buffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    let dataBuffer: Buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const shaObj = new jsSHA("SHA-512", "HEX", {
        hmacKey: { value: keyBuffer.toString('hex'), format: "HEX" },
    });
    shaObj.update(dataBuffer.toString('hex'));
    const hmac = shaObj.getHash("HEX");
    return Buffer.from(hmac, 'hex');
}

export function hmac_sha512(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    return internal(key, data);
}