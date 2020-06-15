/**
 * This file contains methods to test the Rs256 class.
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 14/06/2020
 */

// Import the module
import { Rs256 } from "./mod.ts";
import { readJson } from "https://deno.land/std@v0.57.0/fs/mod.ts";

// Create a new Rs256 instance
const rs256 = new Rs256();

// Create a message
const msg = "hello";

// Load the JSON Keyfile
const json: any = await readJson("./keyfile.json");

// Get the key
const key = json.private_key;

// Create a signature
const signature = rs256.sign(key, msg);

console.log(signature);
