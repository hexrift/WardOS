// Known-answer tests for the pure-JS BLAKE3 the client uses for key ids and manifest
// hashes (node-integration.md §2.3, §7.3). The vectors are the official BLAKE3 inputs
// (byte i is i % 251) hashed by the `blake3` Rust crate the node itself uses; the last
// is the §7.4 public test key and its key id.
import assert from "node:assert/strict";
import { test } from "node:test";

import { blake3Hex } from "../blake3.mjs";

const VECTORS = [
  [0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"],
  [1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"],
  [31, "bda80c7fe2db38be6387b35c870bd7728d67b7b6cc5eb9b0e5c7dcb21ea754c2"],
  [32, "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65"],
  [63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"],
  [64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"],
  [65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"],
  [1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"],
  [1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"],
  [1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"],
  [2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"],
  [2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"],
  [3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"],
  [4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"],
  [5000, "ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836"],
  [8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"],
  [8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"],
  [16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"],
];

test("blake3 matches the reference implementation on every tree shape", () => {
  for (const [length, expected] of VECTORS) {
    const input = Uint8Array.from({ length }, (_, i) => i % 251);
    assert.equal(blake3Hex(input), expected, `input of ${length} bytes`);
  }
});

test("blake3 of the §7.4 public key is its key id", () => {
  const publicKey = Buffer.from(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    "hex",
  );
  assert.equal(
    blake3Hex(publicKey),
    "0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433",
  );
});
