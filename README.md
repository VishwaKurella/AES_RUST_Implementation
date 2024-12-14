# AES Encryption and Decryption Tool

This project implements the AES encryption algorithm, including key expansion, block encryption, and decryption functionalities. The implementation supports multiple key sizes (AES-128, AES-192, AES-256) and incorporates AES-specific operations such as SubBytes, ShiftRows, MixColumns, and AddRoundKey. It also implements the PKCS7 padding scheme for input data to ensure it aligns with the block size of AES (16 bytes).

## Features

- **AES Encryption:** Encrypt plaintext using a secret key.
- **AES Decryption:** Decrypt ciphertext back to plaintext.
- **Key Size Support:** Supports AES with 128-bit, 192-bit, or 256-bit keys.
- **PKCS7 Padding:** Automatically applies PKCS7 padding to input data to ensure the input size is a multiple of 16 bytes.
- **Parallelization:** Encrypts data blocks concurrently for faster execution on multi-core systems.
- **SHA-192 Key Derivation:** Derives a key from an input string using SHA-192 if the input key is not the correct length for AES (16, 24, or 32 bytes).
- **Base64 Encoding/Decoding:** Provides utility to encode ciphertext as Base64 for easier transmission or storage.

## Installation

To build and run this project, you need to have the following tools installed:

- Rust (https://www.rust-lang.org/)
- Cargo (Rust's package manager, which is bundled with Rust)

### Steps to Build and Run

1. Clone the repository:

    ```bash
    git clone https://github.com/VishwaKurella/aes-encryption.git
    cd aes-encryption
    ```

2. Build the project:

    ```bash
    cargo build --release
    ```

3. Run the tool:

    ```bash
    cargo run -- --help
    ```

## Usage

### Encrypting Text

To encrypt a plaintext message, you can use the following command:

```bash
cargo run -- encrypt --key "your_secret_key" --input "Plaintext message"
```

- `--key`: The AES key for encryption. Can be a 16, 24, or 32-byte key.
- `--input`: The plaintext message that will be encrypted.

Example:

```bash
cargo run -- encrypt --key "mysecretkey12345" --input "Hello, World!"
```

### Decrypting Text

To decrypt an AES-encrypted message, use the following command:

```bash
cargo run -- decrypt --key "your_secret_key" --input "EncryptedBase64Text"
```

- `--key`: The AES key used for encryption (must be the same as the key used for encryption).
- `--input`: The Base64 encoded ciphertext.

Example:

```bash
cargo run -- decrypt --key "mysecretkey12345" --input "EncryptedBase64TextHere"
```

### Key Derivation

If the provided key is not of the correct size for AES, it will be hashed using SHA-192 to generate a suitable key. AES supports 128, 192, or 256-bit keys. Any key of length other than 16, 24, or 32 bytes will be hashed to derive the key.

### Command-Line Arguments

The project uses [Clap](https://clap.rs/) for command-line argument parsing. Below are the available commands and arguments:

```bash
aes-encryption
├── encrypt            Encrypt a message
│   ├── --key <key>    AES key for encryption
│   └── --input <input> Message to encrypt
├── decrypt            Decrypt an encrypted message
│   ├── --key <key>    AES key for decryption
│   └── --input <input> Base64-encoded ciphertext
└── --help             Show available commands
```

## Algorithm Explanation

AES operates on a fixed block size of 128 bits (16 bytes). The algorithm follows a series of rounds, where each round performs a combination of substitutions, permutations, and mathematical transformations:

1. **SubBytes:** Each byte of the state is replaced by its corresponding value in the S-Box (Substitution Box).
2. **ShiftRows:** The rows of the state matrix are shifted cyclically to the left.
3. **MixColumns:** Columns of the state matrix are mixed to provide diffusion (except in the final round).
4. **AddRoundKey:** The state is XORed with the round key derived from the original key.

The number of rounds depends on the key size:
- AES-128: 10 rounds
- AES-192: 12 rounds
- AES-256: 14 rounds

## Dependencies

The project uses several libraries to perform cryptographic operations and manage file I/O:

- `base64`: For encoding and decoding Base64 data.
- `clap`: For parsing command-line arguments.
- `rayon`: For parallelizing the block encryption.
- `sha2`: For SHA-256 and SHA-192 hashing.
- `std`: For file I/O and input/output handling.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to fork the repository and submit issues or pull requests. Contributions to improve the efficiency, readability, and security of this tool are welcome!

## Contact

For any issues or inquiries, please contact [vishwa.kurell@gmail.com].
