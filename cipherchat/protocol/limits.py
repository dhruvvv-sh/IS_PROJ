"""Size and length limits for protocol stability and memory exhaustion defense."""

# Maximum allowed size for unencrypted message plaintext (in bytes)
MAX_PLAINTEXT_SIZE: int = 64 * 1024  # 64 KiB (65,536 bytes)

# Maximum allowed size for encrypted ciphertext (in bytes)
# AES-256-GCM appends a 16-byte authentication tag to the plaintext
MAX_CIPHERTEXT_SIZE: int = MAX_PLAINTEXT_SIZE + 16  # 65,552 bytes

# Maximum allowed size for HTTP JSON request bodies (in bytes)
MAX_REQUEST_BODY_SIZE: int = 1024 * 1024  # 1 MiB (1,048,576 bytes)
MAX_JSON_REQUEST_SIZE: int = MAX_REQUEST_BODY_SIZE  # Alias for request body limit

# Maximum allowed size for serialized JSON protocol message envelopes (in bytes)
MAX_JSON_MESSAGE_SIZE: int = 256 * 1024  # 256 KiB (262,144 bytes)

# Maximum allowed character length for identifiers (session_id, sender_id, message_id, etc.)
MAX_ID_LENGTH: int = 256  # 256 characters

# Maximum allowed byte length for session derivation context
MAX_CONTEXT_LENGTH: int = 1024  # 1,024 bytes
