const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");
import base64url from 'base64url';

export function encodeBase64(input: Uint8Array | string) {
  let unencoded = input;
  if (typeof unencoded === 'string') {
    unencoded = encoder.encode(unencoded);
  }
  const CHUNK_SIZE = 0x8000;
  const arr = [];
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, Array.from(unencoded.subarray(i, i + CHUNK_SIZE))));
  }
  return btoa(arr.join(''));
};

export function encode(input: Uint8Array | string) {
  return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

export function decodeBase64(encoded: string): Uint8Array {
  const buffer = base64url.toBuffer(encoded);
  // @ts-ignore
  return new Uint8Array(buffer.buffer, buffer.offset, buffer.length);
};

export const decode = (input: Uint8Array | string) => {
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder.decode(encoded);
  }
  encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  try {
    const bytes = decodeBase64(encoded);
    const resultString = decoder.decode(bytes);
    return resultString;
  } catch {
    throw new TypeError('The input to be decoded is not correctly encoded.');
  }
};
