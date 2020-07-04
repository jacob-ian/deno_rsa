/**
 * This file contains additional functions to assist Rs256.ts and RsaKey.ts.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 01/07/2020
 */

/* IMPORTS */
import {
  randomBigIntByBits,
  randomBigIntByRange,
} from "https://raw.githubusercontent.com/jacob-ian/deno_random_bigint/master/src/randomBigInt.ts"; // TODO change this to the deno.land hosting when possible

/**
   * Convert a hexadecimal byte array to a single Uint8
   * @param array The array of hex values to convert to Uin8
   */
export function hexToLumpedInt(array: string[]): number {
  // Get the hex string
  const hexStr = hexToString(array);

  // Return the integer value
  return parseInt(hexStr);
}

/**
   * Convert an array of hexadecimal bytes to string
   * @param array The array of hexadecimals to convert
   */
export function hexToString(array: string[]): string {
  // Create a hex string
  var hexStr = "0x";

  // Add each value to it
  array.forEach((hex) => {
    hexStr += hex;
  });

  // Return the string
  return hexStr;
}

export function hexToUintDot(array: string[]) {
  // Create output string
  var output = "";

  // Loop through the hex array converting each value to an integer
  array.forEach((octet) => {
    output += `${parseInt(`0x${octet}`)}.`;
  });

  // Remove the last dot
  output = output.slice(0, output.length - 1);

  // Return the string
  return output;
}

/**
   * Calculate the value of base^exponent (mod modulus) for BigInts.
   * @param base the value to be exponentiated
   * @param exponent the value of the exponent
   * @param modulus the modulus
   * @return a BigInt value of the calculation
   */
export function modPow(
  base: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint {
  // To calculate the value of base^exponent (mod modulus), we will use an algorithm by Bruce Schneier
  // Create the value variable and start it at 1
  var value = 1n;

  // Let the base equal its modulo
  var base = base % modulus;

  // Create a loop to loop through the exponent
  while (exponent > 0n) {
    // Check the modulus of the exponent and 2
    if (exponent % 2n === 1n) {
      // Add to the signature
      value = (value * base) % modulus;
    }

    // Bitwise decrease the exponent
    exponent = exponent >> 1n;

    // Change the message variable
    base = (base * base) % modulus;
  }

  // Return the signature
  return value;
}

/**
   * Convert a hex string into an array of hex octets
   * @param string the hex string to convert to an array of octets
   */
export function stringToOctetArray(string: string) {
  // Create an octet array
  var octetsArray: string[] = [];

  // Split the string by characters to create an array
  const strChars: string[] = string.split("");

  // Loop through the characters in the array, lumping them into pairs to put in the EM output
  var i = 0;
  var loop = true;
  while (loop) {
    // Get the current and next characters in the array
    const current = strChars[i];
    const next = strChars[i + 1];

    // Add the octet into the octets array and append the hex identifier 0x
    octetsArray.push(`0x${current}${next}`);

    // If this is the second last character, we can stop the loop now as there are no more octets
    if (i > strChars.length - 4) {
      loop = false;
    } else {
      // Increment the loop to the next octet (two places down)
      i += 2;
    }
  }

  // Return the octet array
  return octetsArray;
}

/**
   * Convert an array of hex strings to a string
   * @param array The array of hex string octets
   */
export function octetArrayToString(array: string[]): string {
  // Create the output string
  var output: string = "";

  // Loop through each item in the array
  array.forEach((octet) => {
    // Add the value to the string without the 0x appended
    const value = octet.replace(/0x/g, "");
    output += value;
  });

  // Return the string
  return output;
}

/**
 * An object to store the found prime numbers
 */
interface Primes {
  p: bigint;
  q: bigint;
}

/**
 * Find two prime numbers with the desired bit size.
 * @param size the bit size (length) of the two prime numbers
 * @return an object with both primes as bigints
 */
export function findPrimes(size: number): Primes {
  // Create an empty array for the prime numbers
  const primeArr: bigint[] = [];

  // Find a random integer with the desired bit size
  var random = randomBigIntByBits(size);

  // Start a while loop to complete primality tests
  var loop = true;
  while (loop) {
    // Check how many random primes have been found
    if (primeArr.length < 2) {
      // Test the number for primality
      if (isPrime(random)) {
        // Add it to the array of primes
        primeArr.push();
      } else {
        // Add to the random integer
        random += 1n;
      }
    } else {
      // We have found two random primes, therefore we can stop
      loop = false;
    }
  }

  // Get the two prime numbers
  const p = primeArr[0];
  const q = primeArr[1];

  // Make sure that the two primes aren't the same
  if (p !== q) {
    // Create an object to output the primes
    const primes: Primes = {
      p: primeArr[0],
      q: primeArr[1],
    };
    return primes;
  } else {
    // Restart the function
    return findPrimes(size);
  }
}

/**
 * A test to determine if an integer is a prime number.
 * @param integer the integer (bigint) to test
 */
export function isPrime(integer: bigint) {
  // Ensure the integer isn't divisible by 2
  if (integer % 2n !== 0n) {
    // We therefore have an odd integer
    // Loop through the Fermat primality test
    var stop = false;
    var i = 3;
    while (!stop) {
      // Check if we are still below the integer
      if (i < integer) {
        // Check the result
        if (integer % BigInt(i) === 0n) {
          // Not a prime number, stop the loop and return false
          stop = true;
          return false;
        } else {
          // Continue the loop
          i++;
        }
      } else {
        // This is a prime number
        stop = true;
        return true;
      }
    }
  } else {
    // This isn't a prime number, it's even
    return false;
  }
}

/**
 * A Miller-Rabin Primality test
 * @param integer An odd integer >= 3 to be tested for primality
 * @param security The number of times to repeat the test: >=1
 * @return true if probable prime
 */
export function millerRabin(integer: bigint, security: number): boolean {
}

export function modInv(): bigint {
  return 0n;
}
