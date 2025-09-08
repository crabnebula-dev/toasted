# NPM Compromise Scanner (Rust Edition)

A high-performance binary scanner for detecting NPM packages compromised with cryptocurrency-stealing malware. (Just written for macOS, pull requested accepted)

## Features

- ⚡ **Blazing Fast** - Written in Rust for maximum performance
- 🔍 **Recursive Scanning** - Automatically finds all NPM lockfiles in your projects
- 📦 **Multi-Format Support** - Handles npm, yarn, and pnpm lockfiles
- 🎨 **Beautiful Output** - Color-coded terminal output with clear warnings
- 📊 **JSON Export** - Machine-readable output for CI/CD pipelines

## Installation

```bash
# Build from source
cargo build --release

# Install to system
make install
```

## Usage

```bash
# Scan current directory
npm-compromise-scanner

# Scan specific directory
npm-compromise-scanner /path/to/project

# Output as JSON
npm-compromise-scanner --format json

# Verbose output
npm-compromise-scanner -v
```

## Compromised Packages Detected

The scanner detects 18 packages that were found to be compromised on September 8th, 2025:
- chalk (299.99m weekly downloads)
- debug (357.6m weekly downloads)
- ansi-styles (371.41m weekly downloads)
- And 15 more...

## More Information

https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised
