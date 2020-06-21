/**
 * This file contains the class and methods to create an RS256 (RSAwithSHA256) signature. The signing methods
 * have been obtained from Section 8.2.1 of RFC 8017 (https://tools.ietf.org/html/rfc8017#section-8.2.1).
 *
 * The PKCS#8 methods have been obtained from RFC 5208 (https://tools.ietf.org/rfc/rfc5208.txt).
 *
 * @author Jacob Ian Matthews
 * @version 1.0 14/06/2020
 */

/* IMPORTS */
import { Sha256 } from "https://deno.land/std@v0.57.0/hash/sha256.ts";
import { RsaKey } from "./RsaKey.ts";

/* INTERFACES */
/**
 * An RSA Private Key object
 */
interface RSAPrivateKey {
  version: number;
  modulus: string;
  publicExponent: number;
  privateExponent: string;
  prime1: string;
  prime2: string;
  exponent1: string;
  exponent2: string;
  coefficient: string;
}

/**
 * A class to generate a RSASSA-PKCS1-V1_5 signature from an input message and a private key.
 */
export class Rs256 {
  /* PROPERTIES */

  /* METHODS */
  constructor() {}

  /**
   *
   * PUBLIC METHODS
   *
   */

  /**
   * Sign a message and create a signature with RSASSA-PKCS1-V1_5.
   * @param key The RSA private key to sign the message with
   * @param message The message to be signed and converted into a signature
   */
  public sign(
    key: string,
    message: string | number[] | Uint8Array,
  ): string {
    // Decode the RSA Private Key string to get the modulus and private exponent
    const rsaPrivateKey = new RsaKey().decode(key);

    // Get the length of the private key's modulus in octets
    const k = (rsaPrivateKey.modulus.length - 2) / 2;

    // Encode the message using the EMSA-PKCS1-v1_5 method
    const EM = this.emsaEncode(message, k);

    // Convert the encoded message into an integer primitive
    const m = this.os2ip(EM);

    // Create a signature integer representative by applying the RSASP1 signature primitive
    // to the RSA private key and the integer message representative
    const s = this.rsasp1(rsaPrivateKey, m);

    // Convert the signature integer representative into an octet string (hex string) signature
    const signature = this.i2osp(s, k);

    // Return the RSASSA-PKCS1-V1_5 signature
    return signature;
  }

  public verify() {}

  /**
   *
   * PRIVATE METHODS
   *
   */

  /**
   * Encode a message using EMSA-PKCS1-v1_5.
   * @param message The message to encode with EMSA-PKCS1-v1_5
   * @param emLen The length of the modulus in octets, and therefore the length of the encoded message
   * @return the encoded message as an array of hex strings (octets)
   */
  private emsaEncode(
    message: string | number[] | Uint8Array,
    emLen: number,
  ): string[] {
    // Hash the message with SHA-256 and encode it with DER in an ASN.1 DigestInfo object
    const T: string = this.digestInfo(message);

    // Let tLen be the length of the DigestInfo object in octets
    const tLen = T.length / 2;

    // Check the length of T against the length of the modulus
    if (!(emLen < tLen + 11)) {
      // Calculate the number of PS octets to add as padding
      const pLen: number = emLen - tLen - 3;

      // Ensure that it is greater than or equal to 8 octets
      if (pLen >= 8) {
        // Create the octet string PS with pLen 0xFF octets
        var PS: string = "";

        // Loop through adding the PS octets
        for (var i = 0; i < pLen; i++) {
          PS += "FF";
        }

        // Create the encoded message string by concatenating PS and T with padding
        const emSpaced = `00 01 ${PS} 00 ${T}`;

        // Remove all whitespace from the string and capitalise all letters
        var emStr = emSpaced.replace(/ /g, "").toUpperCase();

        // Convert the string into an array of hexadecimal octet strings
        const EM = this.stringToOctetArray(emStr);

        // Return the encoded message
        return EM;
      } else {
        // Return an error that the message's length is too long
        throw new Error("The intended encoded message's length is too long");
      }
    } else {
      // The encoded message is too short
      throw new Error("The intended encoded message's length is too short.");
    }
  }

  /**
   * Hash the message and encode it in a DigestInfo ASN.1 object.
   * @param message the message to be encoded
   * @return a hex string with the DigestInfo object
   */
  private digestInfo(message: string | number[] | Uint8Array): string {
    // Hash the message with SHA-256
    const hash: string = new Sha256().update(message).hex();

    // Create the DER encoded DigestInfo with the hash and algorithm identifier
    // The OID for SHA-256 in space delimited hex string is
    const oid: string = "06 09 60 86 48 01 65 03 04 02 01";

    // The NULL parameters for the algorithm's OID are
    const oidParams: string = "05 00";

    // Therefore the AlgorithmIdentifier has a sequence tag of 30 and length of 13 (0x0D), therefore we have
    const algorithmIdentifier: string = `30 0D ${oid} ${oidParams}`;

    // The SHA-256 digest has a length of 32 bytes (0x20), and we can identify an octect string by 0x04
    const digest: string = `04 20 ${hash}`;

    // The DigestInfo sequence's length in decimal can be found as
    const lengthDec: number = 13 + 2 + 2 + 32;

    // We therefore must convert the lengthDec to hexadecimal
    var length = lengthDec.toString(16);

    // Check if the length hexadecimal is a single character
    if (length.length < 2) {
      // Add a zero to pad the hex value
      length = `0${length}`;
    }

    // We can complete the DigestInfo hex string by including the sequence tag and length
    const digestInfoSpaced: string =
      `30 ${length} ${algorithmIdentifier} ${digest}`;

    // Remove all whitespace from the string
    var digestInfo = digestInfoSpaced.replace(/ /g, "");

    // Return the digestInfo hex string
    return digestInfo;
  }

  /**
   * Convert an octet string to a non-negative integer representation
   * @param octetString A hexadecimal string of octets containing the encoded message.
   * @return an integer primitive of the inputted octet string.
   */
  private os2ip(octetString: string[]): bigint {
    // Create a new array of the corresponding decimal integers from the hex string
    var integerArray: number[] = [];

    // Loop through the EM array of hexidecimal octets and parse them as Uint8
    octetString.forEach((octet) => {
      integerArray.push(parseInt(octet));
    });

    // Loop through the new array of integers to find the integer primitive such that
    // x = sum(integerArray[i]*256^(i)), 0 <= i < integerArray.length

    // Create the output integer primitive
    var x: bigint = 0n;

    // Loop through the array of integers
    var i: number;
    for (i = 0; i < integerArray.length; i++) {
      // Get the current integer
      const int = integerArray[i];

      // Calculate the value for this integer
      const value: bigint = BigInt(int) * 256n ** BigInt(i);

      // Add it to the output integer
      x += value;
    }

    // Return the integer primitive of the octet string
    return x;
  }

  /**
   * Create a signature integer representative from the private key and the message integer representative.
   * @param key a valid RSA private key
   * @param message the intger message representative
   * @return a number denoting the integer representative of the signature
   */
  private rsasp1(key: RSAPrivateKey, message: bigint): bigint {
    // Convert the modulus and exponent hex strings to BigInts
    var n = BigInt(key.modulus);
    var d = BigInt(key.privateExponent);

    // Check to see if the message is in the right value range
    if (message < n - 1n) {
      // Calculate the exponentiated modulus such that s = message^d % n
      const signature = this.modPow(message, d, n);

      // Return the signature
      return signature;
    } else {
      // Throw an error
      throw new Error("Message representative out of range.");
    }
  }

  /**
   * Convert an integer representative to an octet string (Integer-to-Octet-String-Primitive)
   * @param x the input's integer representative
   * @param length the length of the outputted string in octets
   * @return a hex string
   */
  private i2osp(x: bigint, xLen: number): string {
    // Check the size
    if (x < 256n ** BigInt(xLen)) {
      // Create a string to hold the hex values
      var octets: string = "";

      // Create a loop that will continue until the x value is 0
      while (x) {
        // Calculate the individual integer from the modulus of x and 256
        const int: number = Number(x % 256n);

        // Convert the integer to a hex value
        const octet = int.toString(16);

        // Add the octet to the octet string
        octets += octet;

        // Re-assign x to be the floor of x/256
        x = x / 256n;
      }

      // Get the length of the octet string
      const length = octets.length / 2;

      // Check the length of the string
      if (length === xLen) {
        // We can return the hex string as it is the correct length
        return octets;
      } else if (length < xLen) {
        // Add padding 00 values to the string
        // Calculate the number of values to add
        const padding = xLen - length;
        for (var i = 0; i < padding; i++) {
          // Add a padding 0x00 value
          octets = `00${octets}`;
        }
        return octets;
      } else {
        throw new Error("Integer is too large.");
      }
    } else {
      // Throw an error that the integer is too large
      throw new Error("Integer is too large.");
    }
  }

  /**
   * Calculate the value of base^exponent (mod modulus) for BigInts.
   * @param base the value to be exponentiated
   * @param exponent the value of the exponent
   * @param modulus the modulus
   * @return a BigInt value of the calculation
   */
  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
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
  private stringToOctetArray(string: string) {
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
}
