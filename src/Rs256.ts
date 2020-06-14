/**
 * This file contains the class and methods to create an RS256 (RSAwithSHA256) signature.
 *
 * @author Jacob Ian Matthews
 * @version 1.0, 14/06/2020
 */

/* IMPORTS */
import { Sha256 } from "https://deno.land/std@v0.57.0/hash/sha256.ts";

/**
 * A class to generate a SASSA-PKCS1-V1_5 signature from an input message and a private key.
 */
export class Rs256 {
  /* PROPERTIES */

  /* METHODS */
  constructor() {}

  /**
   * Sign a message and create a signature with SASSA-PKCS1-V1_5.
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
    const hashValue: number[] = new Sha256().update(message).digest();

    // DER Encode the hash with the algorithm indicator in a DigestInfo ASN1.0 type.
  }

  private digestInfo(algorithmIndicator: any, digest: number[]) {}
}
