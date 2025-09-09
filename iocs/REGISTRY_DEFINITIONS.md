# Package Registry Definitions

This document defines the standard registry identifiers used in IOC files.

## Supported Package Registries

| Registry ID | Full Name | Language/Ecosystem | URL |
|------------|-----------|-------------------|-----|
| `npmjs` | npm Registry | JavaScript/Node.js | https://www.npmjs.com |
| `pypi` | Python Package Index (PyPI) | Python | https://pypi.org |
| `rubygems` | RubyGems.org | Ruby | https://rubygems.org |
| `maven` | Maven Central | Java/JVM | https://search.maven.org |
| `nuget` | NuGet Gallery | .NET/C# | https://www.nuget.org |
| `packagist` | Packagist | PHP | https://packagist.org |
| `hex` | Hex.pm | Elixir/Erlang | https://hex.pm |
| `crates` | crates.io | Rust | https://crates.io |
| `go` | Go Packages | Go | https://pkg.go.dev |

## Usage in IOC Files

In IOC YAML files, specify the registry at both the top level (for the entire file) and optionally override it at the package level:

```yaml
# Top-level registry (default for all packages in this file)
registry: "npmjs"

packages:
  - name: "example-package"
    version: "1.0.0"
    # Package-level registry (overrides the top-level default)
    registry: "npmjs"
```

## Adding New Registries

When adding support for a new package registry:
1. Add it to the table above with a unique, lowercase identifier
2. Use the identifier consistently across all IOC files
3. Update the scanner documentation if needed