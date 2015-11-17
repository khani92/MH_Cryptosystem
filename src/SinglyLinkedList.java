package Part2;

import java.math.BigInteger;

/**
 * This class has the implementation logic for both singly linked list and its
 * node. 
 * */

public class SinglyLinkedList {

	/**
	 * This is a reference to the first node in the list. In case of an empty
	 * list this is null
	 */
	Node head;
	/**
	 * This is a reference to the last node in the list. In case of an empty
	 * list this is null
	 */
	Node tail;

	/**
	 * Test driver for SinglyLinkedList
	 * 
	 * @param args
	 */
	public static void main(String[] args) {

		SinglyLinkedList list = new SinglyLinkedList();
		list.insertAtEnd(new BigInteger("12"));
		list.insertAtEnd(new BigInteger("14"));
		list.insertAtEnd(new BigInteger("16"));
		list.insertAtEnd(new BigInteger("18"));
		System.out.println(list);
		list.reverse();
		System.out.println(list);

	}

	/**
	 * Adds a node to the end of the list. This node contains the BigInteger
	 * data b as its data
	 * 
	 * @param b
	 *            Assumption: If this method is called in a brand new list (with
	 *            head and tail=null), this will just add the node like a normal
	 *            node. It does not require the list to be already populated.
	 * 
	 * postcondition If this method is called on a brand new list with head and
	 *                tail null, a new node is added to the list 
	 * BigTheta No case: Big-Theta (1)
	 * 
	 */

	public void insertAtEnd(BigInteger b) {

		if (isEmpty()) {
			Node node = new Node(b, null);
			head = node;
			tail = node;
		} else {
			Node node = new Node(b);
			tail.setNext(node);
			tail = node;
		}
	}

	/**
	 * Counts the number of nodes in the list. A full traversal of the list is
	 * required for this action
	 * 
	 * @return count of the number of nodes in the singly linked list between
	 *         head and tail, both inclusive
	 * precondition Size of the list is less than INTEGER.MAXVALUE and there
	 *               should not be any loops in the list
	 * postcondition No change or alteration is made to the list while
	 *                traversing. Just a count is maintained.
	 * 
	 * BigTheta No Case: Big Theta(n)
	 */
	public int countNodes() {
		Node cursor;
		int count = 0;

		if (!isEmpty()) {
			cursor = head;

			while (cursor != null) {
				count++;
				cursor = cursor.getNext();
			}
		}
		return count;
	}

	/**
	 * Method to check if list is empty or not
	 * 
	 * @return true if the list empty false otherwise 
	 * BigTheta Big Theta(1)
	 */
	public boolean isEmpty() {
		boolean flag = false;

		if (head == null && tail == null) {
			flag = true;
		}
		return flag;
	}

	/**
	 * Reverses the list
	 * 
	 * precondition List is not recursive and does not contain any loops
	 * postcondition The current list is now reversed. a -> b -> c becomes c ->
	 *                b -> a 
	 * BigTheta Big Theta(n)
	 */
	public void reverse() {
		Node prev, curr, next = null;

		if (!isEmpty()) {
			//Start from the head and swap the head and tail
			curr = head;
			head = tail;
			tail = curr;

			//prev and curr are at the same location at the start of the loop
			prev = curr;
			
			next = curr.getNext();
			tail.setNext(null);

			while (curr != null) {
				// Move current pointer to the next spot
				curr = next;
				//Move next pointer further ahead
				if(curr!=null)next = curr.getNext();
				//Change the pointer location for the current pointer's link.
				if(curr!=null)curr.setNext(prev);
				//Move prev to the current pointer
				prev = curr;
			}

		}
	}

	@Override
	/**Is typically used to print the entire list
	 *@return Returns the char data from the node
	 */
	public java.lang.String toString() {
		StringBuilder s = new StringBuilder();
		Node cursor;

		if (!isEmpty()) {
			cursor = head;
			while (cursor != null) {
				s.append(cursor.toString() + " ");
				cursor = cursor.getNext();
			}
		}
		return s.toString();
	}
}

class Node {

	BigInteger data;
	Node next;

	Node(BigInteger b) {
		this.data = b;
	}

	Node(BigInteger b, Node next) {
		this.data = b;
		this.next = next;
	}

	public BigInteger getData() {
		return data;
	}

	public void setData(BigInteger data) {
		this.data = data;
	}

	public Node getNext() {
		return next;
	}

	public void setNext(Node next) {
		this.next = next;
	}

	@Override
	public String toString() {
		return data.toString();
	}
}