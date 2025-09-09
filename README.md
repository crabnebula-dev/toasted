# Toasted - Package Vulnerability Scanner

A high-performance binary scanner for detecting packages compromised with cryptocurrency-stealing malware. (Just written for macOS, pull requested accepted)

## Features

- ⚡ **Blazing Fast** - Written in Rust for maximum performance
- 🔍 **Recursive Scanning** - Automatically finds all package lockfiles in your projects
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
toasted

# Scan specific directory
toasted /path/to/project

# Output as JSON
toasted --format json

# Verbose output
toasted -v

# Use custom IOC file
toasted --ioc /path/to/custom-iocs.yaml

# Use custom IOC directory
toasted --ioc /path/to/ioc-directory/

# Skip default IOCs from ~/.its-toasted/iocs
toasted --no-default-iocs --ioc /path/to/custom.yaml
```

## IOC Management

The scanner supports loading Indicators of Compromise (IOCs) from external YAML or JSON files.

### Default IOC Location
IOC files are automatically loaded from `~/.its-toasted/iocs/` directory. This directory is created during installation with default IOC files.

### IOC File Format
IOC files can be in YAML or JSON format:

```yaml
name: "NPM Packages Compromised - September 2024"
description: "Description of the compromise"
source: "https://source-url.com"
date: "2024-09-08"
registry: "npmjs"  # Default registry for all packages in this file

packages:
  - name: "package-name"
    version: "1.0.0"
    weekly_downloads: "10m"
    severity: "critical"  # critical, high, medium, low
    registry: "npmjs"  # Package registry (npmjs, pypi, rubygems, maven, nuget, packagist, hex, crates, go)

tags:
  - malware
  - supply-chain-attack
```

See `iocs/REGISTRY_DEFINITIONS.md` for a complete list of supported package registries.

### Adding New IOCs
1. Create a new YAML/JSON file in `~/.its-toasted/iocs/`
2. Follow the format shown above
3. The scanner will automatically load it on next run

### Custom IOC Sources
You can also specify custom IOC files or directories:
- Single file: `--ioc /path/to/ioc.yaml`
- Directory: `--ioc /path/to/ioc-directory/`

## Compromised Packages Detected

The scanner includes built-in detection for 18 packages that were found to be compromised on September 8th, 2025:
- chalk (299.99m weekly downloads)
- debug (357.6m weekly downloads)
- ansi-styles (371.41m weekly downloads)
- And 15 more...

## More Information

https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised
