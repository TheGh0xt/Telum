   git clone <repository-url>
   cd telum
   ```

2. Build the project:
   ```bash
   cargo build
   ```

## Usage

### Running Tests

Run all tests:
```bash
cargo test
```

Run with test coverage:
```bash
cargo test -- --nocapture
```

Run with fuzzing:
```bash
cargo +nightly fuzz run fuzz_payload_without_panic
```

## Project Structure

```
telum/
├── src/
│   ├── lib.rs          # Library entry point
│   ├── protocol.rs     # Protocol definitions (Header, Message, etc.)
│   ├── parser.rs       # Message parsing logic
│   ├── error.rs        # Error handling
│   └── main.rs         # Example usage (if applicable)
├── tests/
│   └── integration_test.rs  # Integration tests
├── Cargo.toml          # Project configuration
└── README.md           # Project documentation
