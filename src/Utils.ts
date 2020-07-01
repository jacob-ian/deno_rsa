/**
 * This file contains additional functions to assist Rs256.ts and RsaKey.ts.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 01/07/2020
 */

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
 * Find two prime numbers with the desired size
 * @param size the bit size (length) of the two prime numbers
 * @return an object with both primes as bigints
 */
export function findPrimes(size: number): Primes {
  const primes: Primes = {
    p: 1n,
    q: 1n,
  };
  return primes;
}

export function modInv(): bigint {
  return 0n;
}

/**
 * Find a random number with a given bit size
 * @param size the bit size
 */
export function randomInt(size: number): bigint {
  // Get the maximum number
  const max = 2n ** BigInt(size);

  // Get the minimum number
  const min = 2n ** BigInt(size - 1);

  // Generate a random number
  const randomNum = Math.random();

  // Convert to an integer by multiplying by its number of decimal places to the power of 10
  const scaling = randomNum.toString().length - 2;
  const scaleFactor = 10 ** scaling;
  const randomScaled = BigInt(randomNum * scaleFactor);

  // Find the random number within the range provided from the size
  const randomRanged = randomScaled * (max - min) + min;

  // Remove the scaling factor and find the floor of the BigInt
  const random = randomRanged / (BigInt(scaleFactor));
  console.log(random);
  console.log(max);
  console.log(min);

  // Check if it is within the range
  if ((random < max) && (random > min)) {
    console.log("in range");
  } else {
    console.log("out of range");
  }

  return 0n;
}
