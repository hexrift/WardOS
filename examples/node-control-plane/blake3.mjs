// BLAKE3-256 in plain JavaScript, hash mode only (no key, no key derivation), for the two
// places the ward-node contract needs it on the control plane: the issuer key id,
// BLAKE3-256 over the 32 raw public-key bytes (node-integration.md §2.3), and the
// capability manifest hash over the manifest bytes as sent (§7.3). Node's `crypto` has
// no BLAKE3, and this client takes no npm dependency, so the reference algorithm is
// written out here; test/blake3.test.mjs holds it to the official vectors on every tree
// shape up to 16 KiB, which covers the 8 KiB a manifest may be.

const IV = Uint32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;
const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function g(state, a, b, c, d, mx, my) {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = rotr(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = rotr(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr(state[b] ^ state[c], 7);
}

function round(state, m) {
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

/** The compression function: 16 state words from a chaining value and a 16-word block. */
function compress(chainingValue, blockWords, counter, blockLen, flags) {
  const state = new Uint32Array(16);
  state.set(chainingValue.subarray(0, 8), 0);
  state.set(IV.subarray(0, 4), 8);
  state[12] = counter >>> 0;
  state[13] = Math.floor(counter / 0x100000000) >>> 0;
  state[14] = blockLen;
  state[15] = flags;
  let block = Uint32Array.from(blockWords);
  for (let i = 0; i < 7; i += 1) {
    round(state, block);
    if (i < 6) {
      const permuted = new Uint32Array(16);
      for (let j = 0; j < 16; j += 1) permuted[j] = block[MSG_PERMUTATION[j]];
      block = permuted;
    }
  }
  for (let i = 0; i < 8; i += 1) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= chainingValue[i];
  }
  return state;
}

function wordsOf(bytes, offset, length) {
  const words = new Uint32Array(16);
  for (let i = 0; i < length; i += 1) {
    words[i >> 2] |= bytes[offset + i] << (8 * (i & 3));
  }
  return words;
}

/** The node that produces a chaining value or, with ROOT added, the root output. */
function output(inputCv, blockWords, counter, blockLen, flags) {
  return {
    chainingValue: () => compress(inputCv, blockWords, counter, blockLen, flags).subarray(0, 8),
    rootBytes: () => {
      const words = compress(inputCv, blockWords, 0, blockLen, flags | ROOT);
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 8; i += 1) {
        bytes[4 * i] = words[i] & 0xff;
        bytes[4 * i + 1] = (words[i] >>> 8) & 0xff;
        bytes[4 * i + 2] = (words[i] >>> 16) & 0xff;
        bytes[4 * i + 3] = (words[i] >>> 24) & 0xff;
      }
      return bytes;
    },
  };
}

/** Hash one chunk (at most 1024 bytes) at `chunkIndex` into its output node. */
function chunkOutput(bytes, start, length, chunkIndex) {
  let cv = IV;
  let offset = start;
  let remaining = length;
  let flags = CHUNK_START;
  // Every block but the last is compressed here; the last is left for the output node so
  // that ROOT can still be added to it when the whole input is one chunk.
  while (remaining > BLOCK_LEN) {
    cv = compress(cv, wordsOf(bytes, offset, BLOCK_LEN), chunkIndex, BLOCK_LEN, flags).subarray(0, 8);
    offset += BLOCK_LEN;
    remaining -= BLOCK_LEN;
    flags = 0;
  }
  return output(cv, wordsOf(bytes, offset, remaining), chunkIndex, remaining, flags | CHUNK_END);
}

function parentOutput(left, right) {
  const block = new Uint32Array(16);
  block.set(left, 0);
  block.set(right, 8);
  return output(IV, block, 0, BLOCK_LEN, PARENT);
}

/** BLAKE3-256 of `input` (a Uint8Array or Buffer) as 32 bytes. */
export function blake3(input) {
  const bytes = input instanceof Uint8Array ? input : Uint8Array.from(input);
  const chunkCount = Math.max(1, Math.ceil(bytes.length / CHUNK_LEN));
  const stack = [];
  for (let index = 0; index < chunkCount - 1; index += 1) {
    let cv = chunkOutput(bytes, index * CHUNK_LEN, CHUNK_LEN, index).chainingValue();
    // Merge completed subtrees: after chunk `index` the stack holds one chaining value per
    // set bit of `index + 1`.
    let total = index + 1;
    while ((total & 1) === 0) {
      cv = parentOutput(stack.pop(), cv).chainingValue();
      total >>= 1;
    }
    stack.push(cv);
  }
  const lastStart = (chunkCount - 1) * CHUNK_LEN;
  let node = chunkOutput(bytes, lastStart, bytes.length - lastStart, chunkCount - 1);
  while (stack.length > 0) {
    node = parentOutput(stack.pop(), node.chainingValue());
  }
  return node.rootBytes();
}

/** BLAKE3-256 of `input` as 64 lowercase hex digits, the spelling every hash has on the wire. */
export function blake3Hex(input) {
  return Buffer.from(blake3(input)).toString("hex");
}
