package Part2;

import java.math.BigInteger;
import java.util.Scanner;

public class MerkleHellmanMainClass {

	public static void main(String[] args) {

		// Preparing sequences for encryption/decryption

		// Populate the super increasing sequence w
		MHEncryptDecryptLogic.populateSuperIncSeq();

		// Get Q value
		BigInteger q = MHEncryptDecryptLogic.getQValue();

		// Get R value
		BigInteger r = MHEncryptDecryptLogic.getRValue();

		// w,q,r constitute the private key for encryption

		// Populate Beta Sequence
		MHEncryptDecryptLogic.populateBetaSeq();

		String text = null;
		int byteNum;

		MHEncryptDecryptLogic cipherObj = new MHEncryptDecryptLogic();

		try (Scanner scanObj = new Scanner(System.in)) {
			System.out
					.println("Enter a string with less than 80 characters to be encrypted");

			// Read the text from console
			text = scanObj.nextLine();

			if (text.length() > 80) {
				System.out.println("String too long try again");
				text = scanObj.nextLine();
			}
			// Get the number the number of bytes in the plain text
			byte[] bytePatternArray = text.getBytes();
			byteNum = bytePatternArray.length;

			System.out.println("Text to be encrypted:");
			System.out.println(text);

			// Store the input string in bit pattern. This pattern might be
			// without the front 0 padding and we want padding.
			String bitPattern = new BigInteger(text.getBytes()).toString(2);

			if (byteNum * 8 != bitPattern.length()) {
				// front 0 padding appended
				int paddingReqd = (byteNum * 8) - bitPattern.length();

				for (int i = 0; i < paddingReqd; i++) {
					bitPattern = "0" + bitPattern;
				}
			}

			BigInteger encryptedSum = cipherObj.getEncryptedSum(bitPattern);

			System.out.println(text + " is encrypted as :");
			System.out.println(encryptedSum.toString());

			BigInteger moduloInverseR = r.modInverse(q);
			BigInteger decryptedSum = (encryptedSum.multiply(moduloInverseR))
					.mod(q);

			String decryptedMessage = cipherObj
					.getDecryptedString(decryptedSum);

			System.out.println("The original string was:");
			System.out.println(decryptedMessage);

		}
	}
}
