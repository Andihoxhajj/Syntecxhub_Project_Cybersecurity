import base64
import json
import os
import sys
from dataclasses import dataclass, asdict
from getpass import getpass
from typing import List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_FILE = "vault.enc.json"
KDF_ITERATIONS = 200_000
KEY_LENGTH = 32  # 256-bit AES


@dataclass
class Entry:
    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""


def create_sample_entries() -> List[Entry]:
    """Create some demo entries so every option has something to work with."""
    return [
        Entry(
            name="Gmail",
            username="you@example.com",
            password="Gm@il-Demo-Pass-123",
            url="https://mail.google.com",
            notes="Demo Gmail account password.",
        ),
        Entry(
            name="Facebook",
            username="you.fb",
            password="Fb-Demo-Pass-456!",
            url="https://facebook.com",
            notes="Demo Facebook account password.",
        ),
        Entry(
            name="Github",
            username="andihoxhaj",
            password="Gh-Demo-Pass-789?",
            url="https://github.com",
            notes="Demo GitHub account password.",
        ),
    ]


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt_vault(entries: List[Entry], master_password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    plaintext = json.dumps([asdict(e) for e in entries]).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "kdf_iterations": KDF_ITERATIONS,
    }


def _decrypt_vault(data: dict, master_password: str) -> List[Entry]:
    try:
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        iterations = data.get("kdf_iterations", KDF_ITERATIONS)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(master_password.encode("utf-8"))
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        raw_list = json.loads(plaintext.decode("utf-8"))
        return [Entry(**item) for item in raw_list]
    except Exception:
        # Wrong password or tampered file
        raise ValueError("Failed to decrypt vault. Wrong master password or corrupted file.")


def load_vault(master_password: str) -> List[Entry]:
    if not os.path.exists(VAULT_FILE):
        return []

    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return _decrypt_vault(data, master_password)


def save_vault(entries: List[Entry], master_password: str) -> None:
    payload = _encrypt_vault(entries, master_password)
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def prompt_entry() -> Entry:
    print("\nAdd new entry")
    name = input("Name (e.g., Gmail): ").strip()
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()
    url = input("URL (optional): ").strip()
    notes = input("Notes (optional): ").strip()
    return Entry(name=name, username=username, password=password, url=url, notes=notes)


def search_entries(entries: List[Entry], query: str) -> List[int]:
    query_lower = query.lower()
    matches = []
    for idx, e in enumerate(entries):
        if (
            query_lower in e.name.lower()
            or query_lower in e.username.lower()
            or query_lower in e.url.lower()
        ):
            matches.append(idx)
    return matches


def print_entry(e: Entry, idx: Optional[int] = None) -> None:
    prefix = f"[{idx}] " if idx is not None else ""
    print(f"\n{prefix}{e.name}")
    print(f"  Username: {e.username}")
    print(f"  Password: {e.password}")
    if e.url:
        print(f"  URL: {e.url}")
    if e.notes:
        print(f"  Notes: {e.notes}")


def main() -> None:
    print("=== Local Password Manager ===")
    master_password = getpass("Enter master password: ")

    try:
        entries = load_vault(master_password)
        if entries:
            print(f"Loaded {len(entries)} entries.")
        else:
            print("New vault (no existing entries).")
            use_samples = input(
                "Create some demo entries so you can test all options? (y/N): "
            ).strip().lower()
            if use_samples == "y":
                entries = create_sample_entries()
                print(f"Added {len(entries)} demo entries. Remember to save.")
    except ValueError as e:
        print(e)
        sys.exit(1)

    while True:
        print(
            "\nChoose an option:\n"
            "  1) Add entry\n"
            "  2) List all entries\n"
            "  3) Search entries\n"
            "  4) Delete entry\n"
            "  5) Save & exit\n"
            "  6) Exit without saving\n"
        )
        choice = input("Option: ").strip()

        if choice == "1":
            entry = prompt_entry()
            entries.append(entry)
            print("Entry added (remember to save).")

        elif choice == "2":
            if not entries:
                print("No entries stored.")
            else:
                for idx, e in enumerate(entries):
                    print_entry(e, idx)

        elif choice == "3":
            q = input("Search query: ").strip()
            matches = search_entries(entries, q)
            if not matches:
                print("No matching entries.")
            else:
                for idx in matches:
                    print_entry(entries[idx], idx)

        elif choice == "4":
            if not entries:
                print("No entries to delete.")
                continue
            try:
                idx = int(input("Index of entry to delete: ").strip())
                if 0 <= idx < len(entries):
                    removed = entries.pop(idx)
                    print(f"Deleted entry '{removed.name}'. (Remember to save.)")
                else:
                    print("Invalid index.")
            except ValueError:
                print("Please enter a valid number.")

        elif choice == "5":
            save_vault(entries, master_password)
            print("Vault saved. Goodbye.")
            break

        elif choice == "6":
            print("Exiting without saving changes.")
            break

        else:
            print("Invalid option. Please choose 1–6.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")

