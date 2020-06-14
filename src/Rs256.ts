/**
 * This file contains the class and methods to create an RS256 (RSAwithSHA256) signature.
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 14/06/2020
 */

/* IMPORTS */
import { Sha256 } from "https://deno.land/std@v0.57.0/hash/sha256.ts";
import * as Asn1 from "https://raw.githubusercontent.com/kjur/jsrsasign/a707d21204f586868f0e4bd415e2563bb6ae7919/src/asn1-1.0.js";

/**
 * A class to generate a RSASSA-PKCS1-V1_5 signature from an input message and a private key.
 */
export class Rs256 {
  /* PROPERTIES */

  /* METHODS */
  constructor() {}

  /**
   * Sign a message and create a signature with RSASSA-PKCS1-V1_5.
   * @param key The RSA private key to sign the message with
   * @param message The message to be signed and converted into a signature
   */
  public sign(key: string, message: string): string {
    // Encode the message using the EMSA-PKCS1-v1_5 method
    const EM = this.emsaEncode(message);

    return "test";
  }

  private emsaEncode(message: string) {
    // Create a hash of the message with SHA-256
    const hash: string = new Sha256().update(message).hex();

    // Encode the hash with DER in an ASN.1 DigestInfo object
    const der: string = this.digestInfo(hash);

    // Get the length of DER in octects
    const derLen: number = der.length / 2;

    // Create an octet string PS
    const PS: string = "";

    // Create the encoded message string by concatenating PS and T with padding
    const EM = `00 01 ${PS} 00 ${der}`;

    return EM;
  }

  private digestInfo(hash: string): string {
    // Create the DER encoded DigestInfo with the hash and algorithm identifier
    // The OID for SHA-256 in hex string is
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
}
