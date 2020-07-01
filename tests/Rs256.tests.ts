/**
 * This file contains methods to test the Rs256 class.
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 14/06/2020
 */

// Import the module
import { Rs256 } from "../mod.ts";
import { readJson } from "https://deno.land/std@v0.57.0/fs/mod.ts";
import { encode } from "https://deno.land/std@v0.57.0/encoding/base64url.ts";

// Create a new Rs256 instance
const rs256 = new Rs256();

// Load the JSON Keyfile
const json: any = await readJson("./keyfile.json");

// Get the key
const key = json.private_key;

// Create the JWT Header
const jwtHead = {
  alg: "RS256",
  typ: "JWT",
};

// Create the JWT Payload/Claim Set
const jwtPayload = {
  iss: json.client_email,
  scope: "https://www.googleapis.com/auth/devstorage.read_write",
  aud: json.token_uri,
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

// Start a timer
const tNow = performance.now();

// Create a signature
const signatureHex = rs256.sign(key, signingInput);

// Calcuate the duration of the signature generation
const duration = performance.now() - tNow;

// Log the time it took to generate the signature
console.log(`Time taken to generate signature: ${duration}ms`);

// Verify the signature
if (rs256.verify(key, signingInput, signatureHex)) {
  // Console log valid
  console.log("Signature verified as valid.");
  // Convert the hex string signature into a Uint8Array
  const signature = new TextEncoder().encode(signatureHex);

  // Base64url encode the signature
  const base64sig = encode(signature);

  // Create the JWT
  const jwt = `${base64header}.${base64payload}.${base64sig}`;

  try {
    // Try get the the response to the Fetch POST
    var res = await fetch(json.token_uri, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body:
        `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
    });

    if (await res.ok) {
      // Successful authentication
      console.log("Success.");
    } else {
      console.log(await res);
    }
  } catch (error) {
    throw error;
  }

  console.log(jwt);
} else {
  // Console log
  console.log("Signature is invalid.");
}
