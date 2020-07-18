/**
 * These are tests for the Utils file.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 1/07/2020
 */
// Import the utils file
import * as Utils from "../src/Utils.ts";

import { createHash } from "https://deno.land/std/hash/mod.ts";
import { encode } from "https://deno.land/std/encoding/base64url.ts";

// Create the JWT Header
const jwtHead = {
  alg: "RS256",
  typ: "JWT",
};

// Create the JWT Payload/Claim Set
const jwtPayload = {
  test: "Testing",
  exp: new Date().getTime() / 1000 + 3600,
  iat: new Date().getTime() / 1000,
};

// Get the UTF-8 integer arrays for the header and payload
const headInt = new TextEncoder().encode(JSON.stringify(jwtHead));
const payInt = new TextEncoder().encode(JSON.stringify(jwtPayload));

// Base64 url encode the header and payload
const base64header = encode(headInt);
const base64payload = encode(payInt);

// Convert the signing input to a UTF-8 array
const signingInput = new TextEncoder().encode(
  `${base64header}.${base64payload}`,
);

const hash1 = createHash("sha256").update(signingInput).toString("hex");
const hash2 = createHash("sha256").update(signingInput).toString("hex");
console.log(hash1);
console.log(hash2);
