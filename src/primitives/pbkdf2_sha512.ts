/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { pbkdf2_sha512 as internal } from '@ton/crypto-primitives';

// pbkdf2_sha512 是一个用于 PBKDF2 (Password-Based Key Derivation Function 2) 算法的实现，
// 该算法使用 SHA-512 哈希函数进行密钥衍生。
// 此方法用于从密码（或密钥）和盐值（salt）生成一个 密钥（derived key），
// 其主要应用是在密码存储和加密密钥管理中，以增强密码的安全性。
export function pbkdf2_sha512(key: string | Buffer, salt: string | Buffer, iterations: number, keyLen: number): Promise<Buffer> {
    return internal(key, salt, iterations, keyLen);
}