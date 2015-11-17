package Part2;

import java.math.BigInteger;
import java.util.Random;

public class MHEncryptDecryptLogic {

	/**
	 * w holds the super increasing sequence. The char limit to the user input
	 * is 80 chars. So the linkedlist w will only have 640 nodes
	 */
	static SinglyLinkedList w = new SinglyLinkedList();

	/**
	 * b holds the public key. The number of nodes in w = nodes in b = 640
	 */
	static SinglyLinkedList b = new SinglyLinkedList();

	/**
	 * q and r are part of the private key and are co-prime to each other.
	 */
	static BigInteger q;
	static BigInteger r;

	/**
	 * This method populates the super increasing sequence. It makes a
	 * superincreasing sequence of random big integers. This will be a part of
	 * the private key and will have a total of 640 nodes.
	 * 
	 * postcondition The static variable w is populated with the super
	 *                increasing sequence. To save execution time q is also
	 *                saved so as to avoid calculating the sum of w again.
	 * BigTheta BigTheta(1)
	 */
	static void populateSuperIncSeq() {
		Random r = new Random();
		BigInteger temp1 = new BigInteger(String.valueOf(r.nextInt()));
		BigInteger big5 = new BigInteger(String.valueOf(r.nextInt()));
		BigInteger tempSum = BigInteger.ZERO;

		// Create a super increasing sequence and store it in the linked
		// list. Max node limit=640

		for (int i = 0; i < 640; i++) {
			w.insertAtEnd(temp1);
			tempSum = tempSum.add(temp1);
			temp1 = temp1.add(tempSum);
			temp1 = temp1.add(big5);
		}
		// Setting q here to save time on traversing again
		q = temp1;
	}

	/**
	 * Getter method for Q-value
	 * 
	 * @return Big Integer Q which is part of the private encryption key
	 */
	static BigInteger getQValue() {
		return q;
	}

	/**
	 * Getter method for R-value
	 * 
	 * @return Big Integer R which is part of the private encryption key
	 * BigTheta Best Case: Big Theta(1)
	 */
	static BigInteger getRValue() {

		Random random = new Random();
		BigInteger temp = new BigInteger(q.bitLength(), random);

		while ((temp.compareTo(q) < 0)
				&& (temp.gcd(q).compareTo(new BigInteger("1")) != 0)) {

			temp = new BigInteger(q.bitLength(), random);
		}
		r = temp;
		return temp;
	}

	/**
	 * This method populates the beta sequence. It makes a public key sequence
	 * of random big integers. This will be a part of the public key and will
	 * have a total of 640 nodes.
	 * 
	 * postcondition The static variable b is populated with the values of
	 *                (w*r)mod q.
	 * BigTheta BigTheta(1)
	 */
	static void populateBetaSeq() {

		Node start = w.head;

		for (int i = 0; i < 640; i++) {
			b.insertAtEnd((start.getData().multiply(r)).mod(q));
			start = start.getNext();
		}
	}

	/**
	 * This method converts the bit pattern from the user input using the Merkle
	 * Hellman encryption logic. It uses w,q,r for this encryption
	 * 
	 * @param bitPattern
	 *            : This is the user input converted to bits
	 * @return Returns the user input into an encrypted single large integer
	 * 
	 * precondition: bitPattern should not be null
	 * BigTheta BestCase - bitPattern.length =1 BigTheta(1)
	 * Bigtheta WorstCase - bitPattern.length = 640 bigTheta(1)
	 */
	public BigInteger getEncryptedSum(String bitPattern) {

		Node encyptStart = b.head;

		BigInteger sum = BigInteger.ZERO;
		BigInteger operand;
		BigInteger product;

		for (int i = 0; i < bitPattern.length(); i++) {
			String bit = bitPattern.charAt(i) + "";
			operand = new BigInteger(bit);
			product = operand.multiply(encyptStart.getData());
			encyptStart = encyptStart.getNext();
			sum = sum.add(product);
		}

		return sum;
	}

	/**
	 * This method converts the decrypted sum into the decrypted bitpattern
	 * which is then converted to the actual user input string
	 * 
	 * @param decryptedSum
	 * @return User input string
	 * BigTheta BigTheta(1) Since we know the loop can only work a max of 640
	 *           times
	 */
	public String getDecryptedString(BigInteger decryptedSum) {

		// Finding the number
		int[] bitArray = new int[640];
		int count = 0;
		Node cursor = w.head;
		Node next = null;
		BigInteger currentItem;

		while (decryptedSum.compareTo(BigInteger.ZERO) != 0) {
			next = cursor.getNext();
			currentItem = cursor.getData();

			// If current item is equal to decrypted sum, or next item is more
			// than decrypted sum, or if we are at the end of the b linkedlist
			if ((currentItem.compareTo(decryptedSum) == 0)
					|| (next != null && next.getData().compareTo(decryptedSum) > 0)
					|| next == null) {
				decryptedSum = decryptedSum.subtract(currentItem);
				
				bitArray[count] = 1;
				count = 0;
				cursor = w.head;
			} else {
				cursor = cursor.next;
				count++;
			}
		}

		StringBuffer s = new StringBuffer();
		for (int i : bitArray) {
			s.append(i + "");
		}
		String decryptedBitString = s.toString();
		StringBuffer message = new StringBuffer();

		for (int i = 0; i < decryptedBitString.length(); i += 8) {
			int a = Integer.parseInt(decryptedBitString.substring(i, i + 8), 2);
			// To avoid square boxes at the end
			if (a != 0) {
				message.append((char) a);
			}

		}

		return message.toString();
	}

}
