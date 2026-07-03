

from __future__ import annotations

import argparse
import sys
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from typing import Dict

ALPHABET_SIZE = 26
ASCII_UPPER_BASE = ord("A")  # 65
ASCII_LOWER_BASE = ord("a")  # 97

class Cipher(ABC):
    """
    Common interface for all cipher implementations.

    Enforces the IPO contract:
        Input  -> Plaintext (raw data)
        Process -> Algorithm + Key
        Output -> Ciphertext (secured)
    """

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Transform plaintext into ciphertext."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Reverse the transformation: ciphertext back into plaintext."""
        raise NotImplementedError

@dataclass
class CaesarCipher(Cipher):
    """
    Mono-alphabetic substitution cipher.

    Encryption:  E_n(x) = (x + n) % 26
    Decryption:  D_n(x) = (x - n) % 26

    where x = character's 0-indexed position in the alphabet (A=0 ... Z=25)
    and n = the shift key.

    Non-alphabetic characters (spaces, digits, punctuation) are passed
    through unchanged, and the original case of each letter is preserved.
    """

    shift: int

    def __post_init__(self) -> None:
        # Normalize the key so it always falls inside a valid rotation
        # range, even if the user passes a negative or oversized shift.
        self.shift = self.shift % ALPHABET_SIZE

    

    def _shift_char(self, char: str, key: int) -> str:
        """Shift a single character by `key` positions, wrapping with % 26."""
        if char.isupper():
            base = ASCII_UPPER_BASE
        elif char.islower():
            base = ASCII_LOWER_BASE
        else:
            return char

        position = ord(char) - base         
        shifted = (position + key) % ALPHABET_SIZE
        return chr(shifted + base)           
    def encrypt(self, plaintext: str) -> str:
        return "".join(self._shift_char(c, self.shift) for c in plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return "".join(self._shift_char(c, -self.shift) for c in ciphertext)



@dataclass
class VigenereCipher(Cipher):
    """
    Polyalphabetic substitution cipher.

    Instead of a single fixed shift, each character of the plaintext is
    shifted by the corresponding letter of a repeating keyword. This
    defeats simple frequency analysis -- the same plaintext letter can
    map to many different ciphertext letters depending on its position.

    Encryption:  C_i = (P_i + K_(i mod len(K))) % 26
    Decryption:  P_i = (C_i - K_(i mod len(K))) % 26
    """

    keyword: str

    def __post_init__(self) -> None:
        if not self.keyword or not self.keyword.isalpha():
            raise ValueError("Vigenère keyword must be a non-empty alphabetic string.")
        self.keyword = self.keyword.upper()

    def _key_shifts(self, length: int) -> list[int]:
        """Generate one shift value per plaintext character (letters only count)."""
        shifts = []
        for i in range(length):
            key_char = self.keyword[i % len(self.keyword)]
            shifts.append(ord(key_char) - ASCII_UPPER_BASE)
        return shifts

    def _transform(self, text: str, sign: int) -> str:
        result_chars = []
        key_index = 0
        key_len = len(self.keyword)

        for char in text:
            if char.isalpha():
                base = ASCII_UPPER_BASE if char.isupper() else ASCII_LOWER_BASE
                key_char = self.keyword[key_index % key_len]
                key_shift = ord(key_char) - ASCII_UPPER_BASE

                position = ord(char) - base
                shifted = (position + sign * key_shift) % ALPHABET_SIZE
                result_chars.append(chr(shifted + base))

                key_index += 1  # Only advance the keyword on actual letters
            else:
                result_chars.append(char)  # Edge case passthrough

        return "".join(result_chars)

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, sign=1)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, sign=-1)


def letter_frequency(text: str) -> Dict[str, float]:
    """
    Calculate the percentage frequency of each letter in `text`.

    Used to demonstrate the Caesar cipher's core vulnerability: the
    frequency *distribution shape* is preserved under a single fixed
    shift, which is exactly what makes frequency analysis attacks
    possible (see Project 2 slide: "The Vulnerability").
    """
    letters_only = [c.upper() for c in text if c.isalpha()]
    if not letters_only:
        return {}

    counts = Counter(letters_only)
    total = len(letters_only)
    return {letter: round((count / total) * 100, 2) for letter, count in sorted(counts.items())}


def brute_force_caesar(ciphertext: str) -> None:
    """
    Demonstrate the cipher's "tiny key space" weakness by trying all
    25 possible shifts and printing every candidate plaintext.
    """
    print("\n--- Brute Force: All 25 Possible Shifts ---")
    for key in range(1, ALPHABET_SIZE):
        candidate = CaesarCipher(shift=key).decrypt(ciphertext)
        print(f"  Shift {key:2d}: {candidate}")


def get_valid_shift(prompt: str = "Enter shift key (1-25): ") -> int:
    """Prompt the user until a valid integer shift key is provided."""
    while True:
        try:
            value = int(input(prompt).strip())
            return value % ALPHABET_SIZE
        except ValueError:
            print("  [Error] Please enter a whole number.")


def get_valid_keyword(prompt: str = "Enter Vigenère keyword (letters only): ") -> str:
    """Prompt the user until a valid alphabetic keyword is provided."""
    while True:
        keyword = input(prompt).strip()
        if keyword.isalpha() and len(keyword) > 0:
            return keyword
        print("  [Error] Keyword must contain only letters (no spaces/numbers).")



MENU = """
================================================================================
   DecodeLabs :: Project 2 -- Basic Encryption & Decryption
================================================================================
  1. Caesar Cipher   - Encrypt & Decrypt
  2. Vigenère Cipher  - Encrypt & Decrypt (Advanced)
  3. Frequency Analysis Demo (why Caesar is a lockbox, not a vault)
  4. Exit
================================================================================
"""


def run_caesar_flow() -> None:
    plaintext = input("\nEnter the message to encrypt: ")
    shift = get_valid_shift()

    cipher = CaesarCipher(shift=shift)
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print("\n--- IPO Summary ---")
    print(f"  Plaintext  (Input)   : {plaintext}")
    print(f"  Key (n)              : {shift}")
    print(f"  Ciphertext (Output)  : {encrypted}")
    print(f"  Decrypted (Validate) : {decrypted}")
    print(f"  Round-trip OK?       : {decrypted == plaintext}")

    if input("\nRun a brute-force demo on this ciphertext? (y/n): ").lower() == "y":
        brute_force_caesar(encrypted)


def run_vigenere_flow() -> None:
    plaintext = input("\nEnter the message to encrypt: ")
    keyword = get_valid_keyword()

    cipher = VigenereCipher(keyword=keyword)
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print("\n--- IPO Summary ---")
    print(f"  Plaintext  (Input)   : {plaintext}")
    print(f"  Keyword              : {keyword}")
    print(f"  Ciphertext (Output)  : {encrypted}")
    print(f"  Decrypted (Validate) : {decrypted}")
    print(f"  Round-trip OK?       : {decrypted == plaintext}")


def run_frequency_demo() -> None:
    plaintext = input("\nEnter a longer message for frequency analysis: ")
    shift = get_valid_shift()
    cipher = CaesarCipher(shift=shift)
    encrypted = cipher.encrypt(plaintext)

    print("\n--- Plaintext Letter Frequency (%) ---")
    for letter, pct in letter_frequency(plaintext).items():
        print(f"  {letter}: {pct:5.2f}%  {'#' * int(pct)}")

    print("\n--- Ciphertext Letter Frequency (%) ---")
    for letter, pct in letter_frequency(encrypted).items():
        print(f"  {letter}: {pct:5.2f}%  {'#' * int(pct)}")

    print(
        "\nNotice: the bar pattern shifts position but keeps the same SHAPE.\n"
        "That preserved shape is what makes frequency analysis attacks possible\n"
        "against a Caesar cipher -- it's a lockbox, not a vault."
    )


def interactive_menu() -> None:
    while True:
        print(MENU)
        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            run_caesar_flow()
        elif choice == "2":
            run_vigenere_flow()
        elif choice == "3":
            run_frequency_demo()
        elif choice == "4":
            print("\nExiting DecodeLabs Cipher Toolkit. Stay secure! 🛡")
            sys.exit(0)
        else:
            print("  [Error] Invalid option. Please choose 1-4.")


# ==============================================================================
# NON-INTERACTIVE (CLI ARGUMENT) MODE
# ==============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DecodeLabs Project 2: Basic Encryption & Decryption Toolkit"
    )
    parser.add_argument(
        "--cipher", choices=["caesar", "vigenere"], default=None,
        help="Cipher type. Omit to launch the interactive menu instead."
    )
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], help="Operation mode.")
    parser.add_argument("--text", help="The text to process.")
    parser.add_argument("--shift", type=int, help="Shift key (Caesar cipher only).")
    parser.add_argument("--keyword", help="Keyword (Vigenère cipher only).")
    return parser


def run_cli(args: argparse.Namespace) -> None:
    if not args.mode or args.text is None:
        print("[Error] --mode and --text are required in CLI mode.")
        sys.exit(1)

    if args.cipher == "caesar":
        if args.shift is None:
            print("[Error] --shift is required for the Caesar cipher.")
            sys.exit(1)
        cipher: Cipher = CaesarCipher(shift=args.shift)
    else:  # vigenere
        if not args.keyword:
            print("[Error] --keyword is required for the Vigenère cipher.")
            sys.exit(1)
        cipher = VigenereCipher(keyword=args.keyword)

    output = cipher.encrypt(args.text) if args.mode == "encrypt" else cipher.decrypt(args.text)
    print(output)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.cipher:
        run_cli(args)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()