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
  public sign(key: string, message: string | number[]): Uint8Array {
    // Encode the message using the EMSA-PKCS1-v1_5 method
    const EM = this.emsaEncode(message);

    // Get the length of the encoded message (the length of the signature) in octets
    const k = EM.length;

    // Convert the encoded message into an integer message representative
    const m = this.os2ip(EM);

    // Create a signature integer representative by applying the RSASP1 signature primitive
    // to the RSA private key and the integer message representative
    const s = this.rsasp1(key, m);

    // Convert the signature integer representative into an octet stream (hex string) signature
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
   * @return the encoded message as an array of hex strings (octets)
   */
  private emsaEncode(message: string | number[]): string[] {
    // Create a hash of the message with SHA-256
    const hash: string = new Sha256().update(message).hex();

    // Encode the hash with DER in an ASN.1 DigestInfo object
    const T: string = this.digestInfo(hash);

    // Create an octet string PS that is 8 octets long with hexadecimal value 0xFF
    const PS: string = "FF FF FF FF FF FF FF FF";

    // Create the encoded message string by concatenating PS and T with padding
    const emSpaced = `00 01 ${PS} 00 ${T}`;

    // Remove all spaces from the string to ensure uniformity
    const emArr = emSpaced.split(" ");
    var emStr: string = "";
    emArr.forEach((element) => {
      emStr += element;
    });

    // Make sure all letters are capitalised (rather than having a mix)
    emStr = emStr.toUpperCase();

    // Convert the string into an array of octets (individual hex strings)
    // Create an octet array
    var EM: string[] = [];

    // Split the string by characters to create an array
    const emChars: string[] = emStr.split("");

    // Loop through the characters in the array, lumping them into pairs to put in the EM output
    var i = 0;
    var loop = true;
    while (loop) {
      // Get the current and next characters in the array
      const current = emChars[i];
      const next = emChars[i + 1];

      // Add the octet into the EM output and append the hex identifier 0x
      EM.push(`0x${current}${next}`);

      // If this is the second last character, we can stop the loop now as there are no more octets
      if (i > emChars.length - 4) {
        loop = false;
      } else {
        // Increment the loop to the next octet (two places down)
        i += 2;
      }
    }

    // Return the encoded message
    return EM;
  }

  private digestInfo(hash: string): string {
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
    const digestInfoDelimited: string = `30 ${length} ${algorithmIdentifier} ${digest}`;

    // Remove all spaces from the string
    const digestInfoArr = digestInfoDelimited.split(" ");
    var digestInfo: string = "";
    digestInfoArr.forEach((element) => {
      digestInfo += element;
    });

    // Return the digestInfo hex string
    return digestInfo;
  }

  /**
   * Convert an octet stream (in hex string array form) to a non-negative integer representation
   * @param encodedMessage A hexadecimal string of octets containing the encoded message.
   * @return a number containng the integer representation of the encoded message
   */
  private os2ip(encodedMessage: string[]): bigint {
    // Create a new array of the corresponding decimal integers from the hex string
    var emInts: number[] = [];

    // Loop through the EM array of hexidecimal octets and parse them as Uint8
    encodedMessage.forEach((element) => {
      emInts.push(parseInt(element));
    });

    // Loop through the new array of integers to find the EM's representing integer such that
    // x = sum(emInts[i]*256^(i)), 0 <= i < emInts.length

    // Create the output number
    var x: bigint = 0n;

    // Loop through the array of integers
    var i: number;
    for (i = 0; i < emInts.length; i++) {
      // Get the current integer
      const int = emInts[i];

      // Calculate the value for this integer
      const value: bigint = BigInt(int * Math.pow(256, i));

      // Add it to the output integer
      x += value;
    }

    // Return the integer representation of the encoded message
    return x;
  }

  /**
   * Create a signature integer representative from the private key and the message integer representative.
   * @param key a valid RSA private key
   * @param message the intger message representative
   * @return a number denoting the integer representative of the signature
   */
  private rsasp1(key: string, message: bigint): bigint {
    // First we need to parse the private key and retrieve the exponent and modulus
    const { modulus, exponent } = this.decodeKey(key);

    // Convert the modulus and exponent hex strings to BigInts
    const n = BigInt(modulus);
    const d = BigInt(exponent);

    // To complete the exponentiated modulus calculation, we will use an algorithm
    // Determine the binary representation of the private exponent
    const dBinary = d.toString(2);

    // Split the binary values into an array for iteration
    const binArr = dBinary.split("");

    // Calculate the initial value (where the binary exponent value is 1)
    var signature = message % n;

    // Loop through the array of binary values. If the binary value is 0, we square the signature and get
    // its modulus. If the binary value is 1, we square the signature and multiply it by the message.
    for (var i = 1; i < binArr.length; i++) {
      // Get the modulo of the signature squared
      signature = signature ** 2n % n;

      // If the binary value is 1, we also multiply the signature by the message and get the modulus
      if (binArr[i].includes("1")) {
        signature = (signature * message) % n;
      }
    }

    // We can now return the signature integer representative
    return signature;
  }

  /**
   * Processes the RSA private key by converting it to hex and decoding the DER ASN.1 object.
   * @param key The RSA Private key
   * @return an object containing the modulus and the exponent.
   */
  private decodeKey(key: string) {
    // Split the key into groups based around the hyphens
    var keySplit = key.split("-----");

    // Remove the first and last parts of the keySplit array
    keySplit = [keySplit[1], keySplit[2], keySplit[3]];

    // Now the first element of the array is now the identifier of the key's version (PKCS1 or PKCS8 (enc or not-enc)),
    // the second element is the base64 encoded key and the third part is the ending statement.
    // Get the base64 encoded key
    const ident: string = keySplit[0];
    const base64: string = keySplit[1];

    // Check if the private key is PKCS1 or PKCS8
    if (ident.includes("BEGIN PRIVATE KEY")) {
      // This is a PKCS8 key, decode it
      const pkcs8Key = new RsaKey().decodePkcs8(base64);

      // Get the modulus and private exponent from the decoded key
      const modulus: string = pkcs8Key.PrivateKey.modulus;
      const exponent: string = pkcs8Key.PrivateKey.privateExponent;

      // Return the modulus and private exponent
      return { modulus, exponent };
    } else if (ident.includes("BEGIN RSA PRIVATE KEY")) {
      // This is a PKCS1 key, decode it
      const pkcs1Key = new RsaKey().decodePkcs1(base64);

      // Get the modulus and private exponent
      const modulus: string = pkcs1Key.modulus;
      const exponent: string = pkcs1Key.privateExponent;

      // Return them both
      return { modulus, exponent };
    } else {
      // Throw an error
      throw new Error(
        "Private key cannot yet be recognised. Please use an unencrypted PKCS8 or PKCS1 key."
      );
    }
  }

  /**
   * Convert an integer representative to an octet string (Integer-to-Octet-Stream-Primitive)
   * @param x the input's integer representative
   * @param length the length of the outputted octet string
   * @return an octet string as a number array of base256 integers (Uint8Array)
   */
  private i2osp(x: bigint, length: number): Uint8Array {
    // Check the inputted integer for its size
    if (x >= BigInt(Math.pow(256, length))) {
      // The size is good, continue
      // Create an array to hold the decimal bytes (integers)
      var ints: number[] = [];

      // Create a loop that will continue until the x value is 0
      while (x) {
        // Calculate the individual integer from the modulus of x and 256
        const int: number = Number(x % 256n);

        // Add the integer to the array of integers
        ints.push(int);

        // Re-assign x to be the floor of x/256
        x = x / 256n;
      }

      // Calculate how many remaining values are needed to meet the octet string length
      const n = length - ints.length;

      // Push n 0s as padding to the integer array
      for (var i = 0; i < n; i++) {
        // Push a 0 digit to the array
        ints.push(0);
      }

      // Reverse the integers array to have the correct order
      ints = ints.reverse();

      // Return the integer array as a Uint8Array
      return new Uint8Array(ints);
    } else {
      // Throw an error since it is too big and return an empty array
      throw new Error("Signature integer representation is too large.");
    }
  }
}
