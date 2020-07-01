/**
 * These are tests for the Utils file.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 1/07/2020
 */
// Import the utils file
import * as Utils from "../src/Utils.ts";

// Test the random number generator
const size = 1024;
const randomInt = Utils.randomInt(size);
console.log(randomInt);
