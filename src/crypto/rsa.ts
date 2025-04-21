import { createPrivateKey, createPublicKey, privateEncrypt, publicDecrypt } from 'crypto'
import {
  sha3_224, sha3_256, sha3_384, sha3_512
} from 'js-sha3'
import { RSADigestAlgorithm, TBytes, TRSAKeyPair } from './interface'
import { base64Decode, base64Encode } from '../conversions/base-xx'
import { stringToBytes, bytesToString } from '../conversions/string-bytes'
import { createSign, createVerify, generateKeyPairSync, generateKeyPair, constants } from 'crypto'

export const pemToBytes = (pem: string): Uint8Array =>
  base64Decode(pem.trim().split(/\r?\n/).slice(1, -1).join(''))

const pemTypeMap = {
  rsaPrivateNonEncrypted: 'RSA PRIVATE KEY',
  rsaPublic: 'PUBLIC KEY',
}

export const bytesToPem = (bytes: Uint8Array, type: keyof typeof pemTypeMap): string => {
  const header = `-----BEGIN ${pemTypeMap[type]}-----\n`
  const footer = `-----END ${pemTypeMap[type]}-----\n`

  const base64 = base64Encode(bytes).replace(/(.{64})/g, '$1\n')
  return `${header}${base64}\n${footer}`
}

function derToPem(der: Uint8Array, type: 'pkcs1' | 'pkcs8' | 'spki'): string {
  const b64 = Buffer.from(der).toString('base64')
  const lines = b64.match(/.{1,64}/g)?.join('\n')
  const header =
    type === 'pkcs1' ? 'RSA PRIVATE KEY' :
    type === 'spki'  ? 'PUBLIC KEY' :
                       'PRIVATE KEY'
  return `-----BEGIN ${header}-----\n${lines}\n-----END ${header}-----`
}

export function rsaSign(
  privateKeyBytes: Uint8Array,
  message: Uint8Array,
  digest: 'SHA256' | 'SHA1' | 'MD5' = 'SHA256'
): Uint8Array {
  const pem = derToPem(privateKeyBytes, 'pkcs1')
  const privateKey = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs1' })
  const signer = createSign(digest)
  signer.update(message)
  signer.end()
  return signer.sign(privateKey)
}

// Digest function map
const digestMap: Record<RSADigestAlgorithm, (msg: Uint8Array) => Uint8Array> = {
  'SHA3-224': msg => Uint8Array.from(sha3_224.array(msg)),
  'SHA3-256': msg => Uint8Array.from(sha3_256.array(msg)),
  'SHA3-384': msg => Uint8Array.from(sha3_384.array(msg)),
  'SHA3-512': msg => Uint8Array.from(sha3_512.array(msg)),
  // Other digests not supported by this implementation
  'SHA256': () => { throw new Error('Use Node.js crypto for SHA256') },
  'SHA1': () => { throw new Error('Use Node.js crypto for SHA1') },
  'MD5': () => { throw new Error('Use Node.js crypto for MD5') },
  'SHA224': () => { throw new Error('Use Node.js crypto for SHA224') },
  'SHA384': () => { throw new Error('Use Node.js crypto for SHA384') },
  'SHA512': () => { throw new Error('Use Node.js crypto for SHA512') },
}

export const rsaKeyPair = async (): Promise<TRSAKeyPair> =>
  new Promise((resolve, reject) => {
    generateKeyPair('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    }, (err, publicKey, privateKey) => {
      if (err) return reject(err)
      resolve({
        rsaPrivate: pemToBytes(privateKey),
        rsaPublic: pemToBytes(publicKey),
      })
    })
  })

export const rsaKeyPairSync = (): TRSAKeyPair => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })

  return {
    rsaPrivate: pemToBytes(privateKey),
    rsaPublic: pemToBytes(publicKey),
  }
}

export function rsaVerify(
  publicKeyBytes: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  digest: 'SHA256' | 'SHA1' | 'MD5' = 'SHA256'
): boolean {
  const pem = derToPem(publicKeyBytes, 'spki')
  const publicKey = createPublicKey({ key: pem, format: 'pem', type: 'spki' })
  const verifier = createVerify(digest)
  verifier.update(message)
  verifier.end()
  return verifier.verify(publicKey, signature)
}

