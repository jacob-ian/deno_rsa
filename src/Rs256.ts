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
import { createHash } from "https://deno.land/std/hash/mod.ts";
import { RsaKey } from "./RsaKey.ts";
import * as Utils from "./Utils.ts";

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
   * @return the signature as a hex string i.e. "0x010d9e"
   */
  public sign(
    key: string,
    message: string | Uint8Array,
  ): string {
    // Decode the RSA Private Key string to get the modulus and private exponent
    const { modulus, privateExponent } = new RsaKey().decodePrivateKey(key);

    // Get the length of the private key's modulus in bits
    const k = modulus.toString(2).length;

    // Encode the message using the EMSA-PKCS1-v1_5 method
    const EM = this.emsaEncode(message, k);

    // Convert the encoded message into an integer primitive
    const m = this.os2ip(EM);

    // Create a signature integer representative by applying the RSASP1 signature primitive
    // to the RSA private key and the integer message representative
    const s = this.rsasp1(modulus, privateExponent, m);

    // Convert the signature integer representative into an octet string (hex string) signature
    const signature = `0x${this.i2osp(s, k)}`;

    // Return the RSASSA-PKCS1-V1_5 signature
    return signature;
  }

  /**
   * Verify that a signature created with RSASSA-PKCS1-V1_5 is valid
   * @param key The RSA Public Key 
   * @param message The message that was sent (hex string)
   * @param signature The signature to be verified (hex string)
   * @return true if the signature is valid, false if it is invalid
   */
  public verify(
    key: string,
    message: string | Uint8Array,
    signature: string,
  ): boolean {
    // Decode the RSA public key and retrieve the public exponent and modulus
    const { modulus, publicExponent } = new RsaKey().decodePublicKey(key);

    // Get the length of the modulus in octets
    const k = modulus.toString(2).length;

    // Check if there is a 0x prepended to the hex string
    if (signature.includes("0x")) {
      // Remove 0x from the signature
      signature = signature.slice(2);
    }

    // Get the length of the signature in octets
    const sigLen = signature.length / 2;

    // Check if the modulus and signature length matches
    if (k === sigLen) {
      // Convert the signature into an array of hex string octets
      const sigArray = Utils.stringToOctetArray(signature);

      // Convert the signature into an integer representative
      const s = this.os2ip(sigArray);

      // Produce an integer message representative by applying RSAVP1 to the signature
      const m = this.rsavp1(modulus, publicExponent, s);

      // Convert the message to an integer representative to get the encoded message
      const emFound = this.i2osp(m, k);

      // Encode the actual message with EMSA-PKCS1-v1_5
      const EM = this.emsaEncode(message, k);

      // Convert the real encoded message to a string
      const emActual = Utils.octetArrayToString(EM);

      console.log(`emFound: ${emFound}`);
      console.log(`emActual: ${emActual}`);

      // Compare the two encoded messages in constant time.
      // If they are the same, the signature is valid.
      if (Utils.constTimeCompStr(emFound, emActual)) {
        // We have a valid signature
        return true;
      } else {
        // The signature is invalid
        return false;
      }
    } else {
      // The signature isn't the same length as the modulus, output invalid
      return false;
    }
  }

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
    message: string | Uint8Array,
    emLen: number,
  ): string[] {
    // Hash the message with SHA-256
    const hash = createHash("sha256").update(message).toString("hex");

    // Create the DER encoded DigestInfo object with the hash
    var T = `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 ${hash}`;

    // Remove all of the spaces from T
    T = T.replace(/\s/g, "");

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
        var emStr = emSpaced.replace(/\s/g, "").toUpperCase();

        // Convert the string into an array of hexadecimal octet strings
        const EM = Utils.stringToOctetArray(emStr);

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
   * Convert an octet string to a non-negative integer representation
   * @param octetString A hexadecimal string of octets containing the encoded message.
   * @return an integer primitive of the inputted octet string.
   */
  private os2ip(octetString: string[]): bigint {
    // Convert the hexadecimal string into an array of integers
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
  private rsasp1(
    modulus: bigint,
    privateExponent: bigint,
    message: bigint,
  ): bigint {
    // Check to see if the message is in the right value range
    if (message < modulus - 1n) {
      // Calculate the exponentiated modulus such that s = message^d % n
      const signature = Utils.modPow(message, privateExponent, modulus);

      // Return the signature
      return signature;
    } else {
      // Throw an error
      throw new Error("Message representative out of range.");
    }
  }

  /**
   * Create an integer message primitive from a signature, public exponent, and modulus
   * @param modulus the modulus as a hex string (0x...)
   * @param publicExponent the public exponent (number)
   * @param signature the signature as an integer primitive
   * @return an integer representative message
   */
  private rsavp1(
    modulus: bigint,
    publicExponent: bigint,
    signature: bigint,
  ): bigint {
    // Check the size of the signature against the modulus
    if (signature < modulus - 1n) {
      // Calculate the message to be: m = s^e mod n
      const message = Utils.modPow(signature, publicExponent, modulus);

      // Return the message
      return message;
    } else {
      // Throw an error
      throw new Error("Signature representative out of range.");
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
        const octet = int.toString(16).toUpperCase();

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
}
