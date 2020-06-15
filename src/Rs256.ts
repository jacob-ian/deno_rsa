/**
 * This file contains the class and methods to create an RS256 (RSAwithSHA256) signature. The signing methods
 * have been obtained from Section 8.2.1 of RFC 8017 (https://tools.ietf.org/html/rfc8017#section-8.2.1).
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 14/06/2020
 */

/* IMPORTS */
import { Sha256 } from "https://deno.land/std@v0.57.0/hash/sha256.ts";

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
  public sign(key: string, message: string): string {
    // Encode the message using the EMSA-PKCS1-v1_5 method
    const EM = this.emsaEncode(message);

    // Convert the encoded message into an integer message representative
    const m = this.os2ip(EM);

    // Create a signature integer representative by applying the RSASP1 signature primitive
    // to the RSA private key and the integer message representative
    const s = this.rsasp1(key, m);

    // Conver the signature integer representative into an octet stream (hex string) signature
    const signature = this.i2osp(s);

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
   * @return the encoded message
   */
  private emsaEncode(message: string): string {
    // Create a hash of the message with SHA-256
    const hash: string = new Sha256().update(message).hex();

    // Encode the hash with DER in an ASN.1 DigestInfo object
    const T: string = this.digestInfo(hash);

    // Get the length of DER in octects
    const tLen: number = T.length / 2;

    // Create an octet string PS that is 8 octets long with hexadecimal value 0xFF
    const PS: string = "FF FF FF FF FF FF FF FF";

    // Create the encoded message string by concatenating PS and T with padding
    const emSpaced = `00 01 ${PS} 00 ${T}`;

    // Remove all spaces from the string
    const emArr = emSpaced.split(" ");
    var EM: string = "";
    emArr.forEach((element) => {
      EM += element;
    });

    // Make sure all letters are capitalised (rather than having a mix)
    EM = EM.toLocaleUpperCase();

    // Return the encoded message
    return EM;
  }

  private digestInfo(hash: string): string {
    // Create the DER encoded DigestInfo with the hash and algorithm identifier
    // The OID for SHA-256 in space delimited hex string is
    const oid: string = "06 09 60 86 48 01 65 03 04 02 01";

    // The NULL parameters for the algorithm's OID are
    const oidParams: string = "05 00";

    // Therefore the AlgorithmIdentifier has a sequence tag of 30 and length of 13, therefore we have
    const algorithmIdentifier: string = `30 13 ${oid} ${oidParams}`;

    // The SHA-256 digest has a length of 32, and we can indicate an octect string by hex code 04
    const digest: string = `04 32 ${hash}`;

    // The DigestInfo sequence's length can be found as
    const length: number = 13 + 2 + 2 + 32;

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
   * Convert an octet stream (in hex string form) to non-negative integers
   * @param encodedMessage A hexadecimal string of octets containing the encoded message.
   */
  private os2ip(encodedMessage: string): number {
    // Create the output number array
    var x: number[];

    // Get the length of the encoded message in octets
    const emLen = encodedMessage.length / 2;

    // Loop through each octet in the encoded message

    // Return the integer
  }

  /**
   * Create a signature integer representative from the private key and the message integer representative.
   * @param key the RSA private key
   * @param message the intger message representative
   */
  private rsasp1(key: string, message: number): number {
    // Return the integer signature
  }

  /**
   * Convert an integer representative to an octet stream (hex string)
   * @param sigInt the signature integer message representative
   */
  private i2osp(sigInt: number): string {}
}
