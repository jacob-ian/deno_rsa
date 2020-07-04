/**
 * These are tests for the Utils file.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 1/07/2020
 */
// Import the utils file
import * as Utils from "../src/Utils.ts";

// Start a clock
const tStart = performance.now();

console.log("finding primes...");
// Find the two prime numbers
const primes = Utils.findPrimes(1024);

// Find the duration
const tEnd = performance.now();

console.log(primes);
console.log(`Time taken: ${tEnd - tStart}ms`);
