/**
 * Generate or decode an RSA Key pair.
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 17/06/2020
 */

/* IMPORTS */
import * as Utils from "./Utils.ts";
import { randomPrime } from "https://deno.land/x/random_primes/mod.ts";

/* INTERFACES */
/**
 * A PrivateKeyInfo object
 */
interface PrivateKeyInfo {
  algorithm: string;
  PrivateKey: RSAPrivateKey;
}

/**
 * An RSA Private Key object
 */
interface RSAPrivateKey {
  version: number;
  modulus: bigint;
  publicExponent: bigint;
  privateExponent: bigint;
  prime1: bigint;
  prime2: bigint;
  exponent1: bigint;
  exponent2: bigint;
  coefficient: bigint;
}

/**
 * An RSA Public Key object
 */
interface RSAPublicKey {
  modulus: bigint;
  publicExponent: bigint;
}

/**
 * The RSA Keyset output object (encoded)
 */
interface RSAKeyset {
  privateKey: string;
  publicKey: string;
}

/* CLASSES */

/**
 * An RSA Key generation and decoding class
 */
export class RsaKey {
  /* PROPERTIES */

  /* METHODS */
  constructor() {}

  /**
   *
   * PUBLIC METHODS
   *
   */

  /**
   * Decode an RSA Private Key into a usable object.
   * @param key The RSA Private key as a string
   * @return an object containing the decoded ASN.1 object
   */
  public decodePrivateKey(key: string): RSAPrivateKey {
    // Check for the version of the RSA key by examining the preface
    // Split the key into groups based around the hyphens
    var keySplit = key.split("-----");

    // Remove the first and last parts of the keySplit array
    keySplit = [keySplit[1], keySplit[2], keySplit[3]];

    // Now the first element of the array is now the identifier of the key's version (PKCS1 or PKCS8),
    // the second element is the base64 encoded key and the third part is the ending statement.
    // Get the base64 encoded key
    const ident: string = keySplit[0];
    const base64: string = keySplit[1];

    // Check the version
    if (ident.includes("BEGIN PRIVATE KEY")) {
      // The key is encoded in PKCS#8, therefore it is the RSA Private key wrapped in a
      // PrivateKeyInfo ASN.1 object
      // Decode using PKCS#8 and return the decoded RSA Private Key
      return this.decodePrivatePkcs8(base64).PrivateKey;
    } else if (ident.includes("BEGIN RSA PRIVATE KEY")) {
      // The key is encoded with PKCS#1, meaning the key is not wrapped in an 'info' object
      // Decode the PKCS#1 key
      return this.decodePrivatePkcs1(base64);
    } else {
      // Throw an error since it hasn't been encoded in a supported style
      throw new Error(
        "Please use an unencrypted PKCS#8 or PKCS#1 RSAwithSHA256 Private key.",
      );
    }
  }

  /**
   * Decode an RSA Public key into a usable object.
   * @param key The RSA Public Key as a string
   * @return an object containing the decoded ASN.1 object.
   */
  public decodePublicKey(key: string): RSAPublicKey {
  }

  /**
   * Generate a private and public RSA Key set.
   * @param length The bit-length of the modulus to create.
   * @return an object containing the private and public RSA keys as strings.
   */
  public generateKeys(length: number): RSAKeyset {
    // Find the bit-length of the prime numbers
    const primeLen = length / 2;

    // Generate two random prime numbers
    var p = 0n;
    var q = 0n;
    var gen = true;
    while (gen) {
      // Generate the two prime numbers
      p = randomPrime(primeLen, 6);
      q = randomPrime(primeLen, 6);

      // Make sure they aren't equal
      if (p !== q) {
        // Stop the loop
        gen = false;
      }
    }

    // Calculate the modulus
    const modulus = p * q;

    // Calculate the variable phi for the moduluar inverse calculation
    const phi = (p - 1n) * (q - 1n);

    // Get the RSA Public exponent
    const publicExponent = BigInt(65537);

    // Calculate the RSA private exponent to be d = e^-1 mod phi
    const privateExponent = Utils.modInv(publicExponent, phi);

    // Calculate the first exponent
    const exponent1 = privateExponent % (p - 1n);

    // Calculate the second exponent
    const exponent2 = privateExponent % (q - 1n);

    // Calculate the coefficient
    const coefficient = q ** (-1n) % p;

    // Create the unencoded private key
    const privateKey: RSAPrivateKey = {
      version: 0,
      modulus: modulus,
      publicExponent: publicExponent,
      privateExponent: privateExponent,
      prime1: p,
      prime2: q,
      exponent1: exponent1,
      exponent2: exponent2,
      coefficient: coefficient,
    };

    // Create the unencoded public key
    const publicKey: RSAPublicKey = {
      modulus: modulus,
      publicExponent: publicExponent,
    };

    // Create the output object
    const output: RSAKeyset = {
      privateKey: this.encodePrivateKey(privateKey),
      publicKey: this.encodePublicKey(publicKey),
    };

    // Return the output
    return output;
  }

  /**
   *
   * PRIVATE METHODS
   *
  */

  /**
   * Process a PKCS8 RSA Key and return the decoded ASN1.0 object
   * @param key The PKCS8 RSA Key (base64 encoded)
   * @return a decoded ASN.1 object
   */
  private decodePrivatePkcs8(key: string): PrivateKeyInfo {
    // Decode the base64 string into an array of hexadecimal bytes
    var hexKey = this.base64ToHex(key);

    // Skip over adding the version parameter to the object
    // Search for the second instance of SEQUENCE in the key (the AlgorithmIdentifier ASN1 object)
    const algorithmIdPos = hexKey.indexOf("30", 1);

    // Find the number of length octets in the sequence
    const algIdLen = this.getLength(hexKey, algorithmIdPos)[1];

    // Get the position of the Algorithm OID Identifier
    const algOidPos = algorithmIdPos + 1 + algIdLen;

    // Get the length of the OID and the number of length octets
    const algOidLen = this.getLength(hexKey, algOidPos);

    // Get the algorithm OID
    const algorithmOid = hexKey.slice(
      algOidPos + 1 + algOidLen[1],
      algOidPos + 1 + algOidLen[1] + algOidLen[0],
    );

    // Convert the hexadecimal representation of the OID into a uint8 separated by dots (I can't figure out TLV)
    const oidTlv = Utils.hexToUintDot(algorithmOid);

    // Now we can find the RSAPrivateKey inside the rest of the hexadecimal key
    // Get the position of the Private Key's octet string
    const keyPos = algOidPos + algOidLen[1] + algOidLen[0];

    // Get the next occurring SEQUENCE, the RSA Private Key
    var rsaKey = hexKey.slice(hexKey.indexOf("30", keyPos));

    // Create a PrivateKeyInfo object
    var privateKeyInfo: PrivateKeyInfo = {
      algorithm: oidTlv,
      PrivateKey: this.decodeRsaKey(rsaKey),
    };

    // Return the PrivateKeyInfo object
    return privateKeyInfo;
  }

  /**
   * Process a PKCS1 RSA Key and return the decoded ASN1.0 object
   * @param key The PKCS1 RSA Key (base64 encoded)
   * @return a decoded ASN.1 object
   */
  private decodePrivatePkcs1(key: string): RSAPrivateKey {
    // Decode the base64 key to hex
    const keyHex = this.base64ToHex(key);

    // Decode the RSA Private Key
    return this.decodeRsaKey(keyHex);
  }

  /**
   * Decode the DER encoded RSA Key and return a RSAPrivateKey
   * @param key The RSA key in hexadecimal byte array form
   */
  private decodeRsaKey(key: string[]): RSAPrivateKey {
    // Extract the integer ASN.1 objects hex arrays from the key (after the first sequence)
    const from = key.indexOf("02");
    const hexArray = this.extractValues(key.slice(from), "02");

    // The first value is the version
    const version = parseInt(`0x${hexArray[0]}`);

    // The second value is the modulus. Remove the 0x00 padding.
    var modulusArr = hexArray[1].slice(1);
    const modulus = BigInt(`0x${modulusArr.toString().replace(/,/g, "")}`);

    // The third value is the public exponent
    const publicExponent = BigInt(
      `0x${hexArray[2].toString().replace(/,/g, "")}`,
    );

    // The fourth value is the private exponent
    const privateExponent = BigInt(
      `0x${hexArray[3].toString().replace(/,/g, "")}`,
    );

    // The fifth value is the first prime number p
    const prime1 = BigInt(`0x${hexArray[4].toString().replace(/,/g, "")}`);

    // The sixth value is the second prime number q
    const prime2 = BigInt(`0x${hexArray[5].toString().replace(/,/g, "")}`);

    // The seventh value is d mod (p-1)
    const exponent1 = BigInt(`0x${hexArray[6].toString().replace(/,/g, "")}`);

    // The eighth value is d mod (q-1)
    const exponent2 = BigInt(`0x${hexArray[7].toString().replace(/,/g, "")}`);

    // The final value is the coefficient Qinv mod p
    const coefficient = BigInt(
      `0x${hexArray[8].toString().replace(/,/g, "")}`,
    );

    // We can now output the RSAPrivateKey object
    const output: RSAPrivateKey = {
      version: version,
      modulus: modulus,
      publicExponent: publicExponent,
      privateExponent: privateExponent,
      prime1: prime1,
      prime2: prime2,
      exponent1: exponent1,
      exponent2: exponent2,
      coefficient: coefficient,
    };
    return output;
  }

  /**
   * Extract the octet strings for each value of intended type
   * @param array the hexadecimal array of the DER encoded ASN.1 object
   * @param identifier the identifier of the type to extract values of e.g. ("02") for integer
   */
  private extractValues(array: string[], identifier: string): string[][] {
    // Create an output array of string arrays
    var output: string[][] = [];

    // Create a loop to continuously extract the hex arrays
    // for each value until there are none left
    while (array.length) {
      // Check if there is a value to work with
      if (array[0]) {
        // Get the next instance of the identifier
        var i = array.indexOf(identifier);

        // Get the lengths of the current value and
        // the number of length octets for this value
        var lengths = this.getLength(array, i);
        var len = lengths[0];
        var numLen = lengths[1];

        // Check if this is an instance of the identifier
        if (array[i].includes(identifier)) {
          // Get the hex array for this value
          var hexArr = this.slice(array, i, lengths);

          // Add the hex array to the output
          output.push(hexArr);
        }

        // Get the array cutoff value to shorten the array
        var j = i + 1 + numLen + len;

        // Shorten the array to include just the next values
        array = array.slice(j);
      } else {
        // Force the length to 0
        array.length = 0;
      }
    }

    // Return the output array
    return output;
  }

  /**
   * Decode base64 into a hexadecimal array
   * @param base64 A string containing the base64 encoded data
   */
  private base64ToHex(base64: string): string[] {
    // Decode the base64 into binary
    const bin = atob(base64);

    // Create an array to store the hexadecimals
    var hexArray: string[] = [];

    // Loop through the binary characters in the binary string and convert them to hexadecimal
    for (var i = 0; i < bin.length; i++) {
      // Get the hex value for the current character
      var hex = bin.charCodeAt(i).toString(16);

      // Check if a '0' needs to be added to the hex to pad the value
      if (hex.length < 2) {
        hex = `0${hex}`;
      }

      // Capitalise the hex value if needed
      hex = hex.toUpperCase();

      // Push the hex code into the array
      hexArray.push(hex);
    }

    // Return the hexadecimal array of strings
    return hexArray;
  }

  /**
   * Get the integer length of a particular ASN.1 type in octets
   * @param hexArray The array of hexadecimal bytes of DER ASN.1
   * @param pos The position of the identifier for the type
   * @return number[] with the first item being the length and the second item the number of length octets
   */
  private getLength(hexArray: string[], pos: number): number[] {
    // Get the first length octet
    const firstLen = hexArray[pos + 1];

    // Create a variable to hold the count of length octets there are
    var octetCount = 1;

    // Check if long or short length is used
    if (firstLen.charAt(0).includes("8")) {
      // Long length is used, get the number of length octets succeeding the current octet
      octetCount = parseInt(firstLen.charAt(1));

      // Get the array of length octets
      const octets = hexArray.slice(pos + 2, pos + 2 + octetCount);

      // Convert to a string to be parsed into an integer
      var octetStr = "0x";
      octets.forEach((octet) => {
        octetStr += octet;
      });

      // Add one more to the octet count for the indicating length octet
      octetCount++;

      // Return the length in bytes of the ASN.1 type and number of length octets
      return [parseInt(octetStr), octetCount];
    } else {
      // Return the calculated short form length
      return [parseInt(`0x${firstLen}`), octetCount];
    }
  }

  /**
   * Convert an OID from hexadecimal bytes to a ASN.1 TLV
   * @param oidHex The hexadecimal array of an OID
   */
  private oidHexToTlv(oidHex: string[]): string {
    // Group the OID into 6 integer blocks
    var oid1 = parseInt(`0x${oidHex[0]}`);
    var oid2 = parseInt(`0x${oidHex[1]}${oidHex[2]}`);
    var oid3 = parseInt(`0x${oidHex[3]}${oidHex[4]}${oidHex[5]}`);
    var oid4 = parseInt(`0x${oidHex[6]}`);
    var oid5 = parseInt(`0x${oidHex[7]}`);
    var oid6 = parseInt(`0x${oidHex[8]}`);

    // Change the first OID block into two dot separated integers where z = 40x + y, therefore integer x = min(|z/40|, 2) and y = z -40x
    let x = Math.min(Math.abs(oid1 / 40), 2);
    let y = oid1 - 40 * x;
    var oidFirst = `${x}.${y}`;

    // We can now return the constructed TLV OID
    return `${oidFirst}.${oid2}.${oid3}.${oid4}.${oid5}.${oid6}`;
  }

  /**
   * Get a type out of a hexadecimal byte array based on the
   * position of the type's identifier
   * @param array An array to collect a section from
   * @param identPos The position of the ASN1.0 identifier
   * @param lengthArr the array for this identifier generated
   * by this.getLength()
   */
  private slice(
    array: string[],
    identifierPos: number,
    lengthArr: number[],
  ): string[] {
    // Get the length of the array to take
    const length = lengthArr[0];

    // Get the number of length octets
    const lenOctets = lengthArr[1];

    // Get the starting point of the array
    const start = identifierPos + 1 + lenOctets;

    // Get the ending point of the array
    const end = start + length;

    // Get the section of the array
    const slice = array.slice(start, end);

    // Return the slice
    return slice;
  }

  private encodePrivateKey(key: RSAPrivateKey): string {
  }

  private encodePublicKey(key: RSAPublicKey): string {
  }
}
