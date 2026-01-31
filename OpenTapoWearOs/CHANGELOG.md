# Changelog

## [Unreleased] - 2026-01-31

### Added
- **KLAP Protocol Support**: Added full support for the KLAP authentication protocol required by devices with updated TP-Link Tapo firmware
  - New `KlapCryptoUtils` class for SHA-1/SHA-256 hashing and secure random byte generation
  - New `KlapCipher` class for AES-128-CBC encryption/decryption with sequence-based IV
  - New `KlapProtocol` class implementing the 2-step handshake authentication flow
- **Automatic Protocol Detection**: TapoClient now automatically tries KLAP protocol first, then falls back to legacy passthrough protocol for backward compatibility

### Fixed
- **Device Discovery**: P110 and other devices with updated firmware can now be discovered and authenticated
- **Device Control**: Fixed control commands (on/off toggle) not working by updating Device class to use IP-based TapoClient constructor, enabling KLAP protocol for all device operations

### Changed
- `TapoClient`: Now supports both KLAP and passthrough protocols with automatic detection
  - Added `ProtocolType` enum to track active protocol
  - Added `klapProtocol` field for KLAP protocol handler
  - Updated `login()` method to attempt KLAP first, fallback to passthrough on failure
  - Refactored request execution to route through appropriate protocol
- `Device`: Changed `client` from `val` to `lateinit var` to enable IP-based initialization
  - Now parses IP address string and creates TapoClient with IP constructor
  - Enables KLAP protocol support for device control commands

### Technical Details
- KLAP authentication uses SHA256(SHA1(username) + SHA1(password)) for auth hash
- Two-step handshake: handshake1 exchanges seeds, handshake2 verifies session
- Requests encrypted with AES-128-CBC using derived key/IV from local/remote seeds
- Each request includes SHA-256 signature for integrity verification
- Sequence counter ensures request ordering and prevents replay attacks

### Compatibility
- ✅ Fully backward compatible with devices using legacy passthrough protocol
- ✅ Supports devices with updated firmware requiring KLAP protocol
- ✅ All existing device models continue to work (P100, P110, L510, L520, L530, L610, L630)
