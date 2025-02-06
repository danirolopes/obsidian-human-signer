# Obsidian Editor Change Tracker

A secure and reliable plugin for Obsidian that tracks and logs all changes made to your notes, providing a detailed audit trail of modifications with cryptographic verification.

## Features

- **Detailed Change Tracking**: Records all edits made to your notes, including:
  - Text additions and deletions
  - Cursor position changes
  - Timestamps for each modification
  - Key hold times for typing analysis

- **Secure Logging**:
  - Cryptographic signing of log entries using RSA private key
  - Hash verification to ensure log integrity
  - Automatic detection and fixing of log inconsistencies

- **Flexible Configuration**:
  - Support for custom private key location
  - Option to use external signing scripts
  - Automatic key generation if none exists

## Installation

1. Open Obsidian Settings
2. Navigate to Community Plugins and disable Safe Mode
3. Click Browse and search for "Editor Change Tracker"
4. Install the plugin
5. Enable the plugin in your list of installed plugins

## Configuration

1. Go to Settings > Editor Change Tracker
2. Configure the key path:
   - Default: `.obsidian/private_key.pem`
   - Can be changed to a custom path or script location

## How It Works

The plugin monitors all changes made to your notes and creates detailed log entries containing:
- Timestamps of modifications
- Type of change (addition/deletion)
- Position of changes
- Key press durations
- Cryptographic signatures for verification

All logs are automatically verified for consistency and integrity using:
- SHA-256 hashing
- RSA digital signatures
- Automatic inconsistency detection and repair

## Security

The plugin uses industry-standard cryptographic methods to ensure the integrity of your editing history:
- RSA private/public key encryption
- SHA-256 hashing for content verification
- Automatic validation of log file integrity
- Secure storage of cryptographic keys

## Development

To build the plugin locally:

1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the plugin:
   ```bash
   npm run dev
   ```

## Requirements

- Obsidian v0.15.0 or higher
- Node.js for development

## License

MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or have questions:
1. Check the [GitHub Issues](https://github.com/danirolopes/obsidian-editor-change-tracker/issues)
2. Create a new issue if your problem hasn't been reported
3. For security-related concerns, please report them privately

---

For more information about Obsidian plugins, visit [Obsidian Plugin Documentation](https://docs.obsidian.md/Plugins/Getting+started/Build+a+plugin).
