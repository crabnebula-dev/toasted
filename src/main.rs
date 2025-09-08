use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use walkdir::WalkDir;

/// NPM Compromised Package Scanner
/// Detects packages compromised with cryptocurrency-stealing malware
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan (defaults to current directory)
    #[clap(default_value = ".")]
    directory: String,

    /// Output format (text, json)
    #[clap(short, long, default_value = "text")]
    format: String,

    /// Suppress colored output
    #[clap(short = 'n', long)]
    no_color: bool,

    /// Show verbose output
    #[clap(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct CompromisedPackage {
    name: String,
    version: String,
    weekly_downloads: String,
}

#[derive(Debug, Clone, Serialize)]
struct DetectedPackage {
    name: String,
    version: String,
    path: String,
    location: String,
}

#[derive(Debug, Serialize)]
struct Finding {
    file: PathBuf,
    lockfile_type: String,
    packages: Vec<DetectedPackage>,
}

#[derive(Debug, Serialize)]
struct ScanResults {
    scanned_files: usize,
    findings: Vec<Finding>,
    errors: Vec<String>,
}

// NPM lockfile structures
#[derive(Deserialize, Debug)]
struct NpmLockfileV1 {
    dependencies: Option<HashMap<String, NpmDependency>>,
}

#[derive(Deserialize, Debug)]
struct NpmLockfileV2 {
    packages: Option<HashMap<String, NpmPackage>>,
    dependencies: Option<HashMap<String, NpmDependency>>,
}

#[derive(Deserialize, Debug)]
struct NpmDependency {
    version: Option<String>,
    dependencies: Option<HashMap<String, NpmDependency>>,
}

#[derive(Deserialize, Debug)]
struct NpmPackage {
    version: Option<String>,
    dependencies: Option<HashMap<String, String>>,
}

// PNPM lockfile structures
#[derive(Deserialize, Debug)]
struct PnpmLockfile {
    dependencies: Option<HashMap<String, PnpmDependencyVersion>>,
    packages: Option<HashMap<String, PnpmPackage>>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum PnpmDependencyVersion {
    String(String),
    Object(PnpmDependency),
}

#[derive(Deserialize, Debug)]
struct PnpmDependency {
    version: String,
}

#[derive(Deserialize, Debug)]
struct PnpmPackage {
    resolution: Option<PnpmResolution>,
    dependencies: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Debug)]
struct PnpmResolution {
    integrity: Option<String>,
}

struct Scanner {
    compromised_packages: HashMap<String, CompromisedPackage>,
    results: ScanResults,
    args: Args,
}

impl Scanner {
    fn new(args: Args) -> Self {
        let mut compromised_packages = HashMap::new();
        
        // List of compromised packages from the Aikido.dev report with specific versions
        let packages = vec![
            ("backslash", "0.2.1", "0.26m"),
            ("chalk-template", "1.1.1", "3.9m"),
            ("supports-hyperlinks", "4.1.1", "19.2m"),
            ("has-ansi", "6.0.1", "12.1m"),
            ("simple-swizzle", "0.2.3", "26.26m"),
            ("color-string", "2.1.1", "27.48m"),
            ("error-ex", "1.3.3", "47.17m"),
            ("color-name", "2.0.1", "191.71m"),
            ("is-arrayish", "0.3.3", "73.8m"),
            ("slice-ansi", "7.1.1", "59.8m"),
            ("color-convert", "3.1.1", "193.5m"),
            ("wrap-ansi", "9.0.1", "197.99m"),
            ("ansi-regex", "6.2.1", "243.64m"),
            ("supports-color", "10.2.1", "287.1m"),
            ("strip-ansi", "7.1.1", "261.17m"),
            ("chalk", "5.6.1", "299.99m"),
            ("debug", "4.4.2", "357.6m"),
            ("ansi-styles", "6.2.2", "371.41m"),
        ];
        
        for (name, version, downloads) in packages {
            compromised_packages.insert(
                format!("{}@{}", name, version),
                CompromisedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    weekly_downloads: downloads.to_string(),
                },
            );
        }
        
        Scanner {
            compromised_packages,
            results: ScanResults {
                scanned_files: 0,
                findings: Vec::new(),
                errors: Vec::new(),
            },
            args,
        }
    }
    
    fn scan_directory(&mut self, dir: &Path) -> Result<()> {
        let exclude_dirs: HashSet<&str> = ["node_modules", ".git", "dist", "build", ".next", "target"]
            .iter()
            .cloned()
            .collect();
        
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    if let Some(name) = e.file_name().to_str() {
                        return !exclude_dirs.contains(name);
                    }
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    if self.is_lockfile(filename) {
                        if self.args.verbose {
                            println!("{} {}", "Scanning:".cyan(), entry.path().display());
                        }
                        
                        if let Err(e) = self.scan_lockfile(entry.path()) {
                            self.results.errors.push(format!(
                                "{}: {}",
                                entry.path().display(),
                                e
                            ));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn is_lockfile(&self, filename: &str) -> bool {
        matches!(
            filename,
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "pnpm-lock.yml"
        )
    }
    
    fn scan_lockfile(&mut self, path: &Path) -> Result<()> {
        self.results.scanned_files += 1;
        
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let detected_packages = match filename {
            "package-lock.json" => self.parse_npm_lockfile(&content)?,
            "yarn.lock" => self.parse_yarn_lockfile(&content)?,
            "pnpm-lock.yaml" | "pnpm-lock.yml" => self.parse_pnpm_lockfile(&content)?,
            _ => Vec::new(),
        };
        
        if !detected_packages.is_empty() {
            self.results.findings.push(Finding {
                file: path.to_path_buf(),
                lockfile_type: self.get_lockfile_type(filename),
                packages: detected_packages,
            });
        }
        
        Ok(())
    }
    
    fn get_lockfile_type(&self, filename: &str) -> String {
        match filename {
            "package-lock.json" => "npm".to_string(),
            "yarn.lock" => "yarn".to_string(),
            "pnpm-lock.yaml" | "pnpm-lock.yml" => "pnpm".to_string(),
            _ => "unknown".to_string(),
        }
    }
    
    fn parse_npm_lockfile(&self, content: &str) -> Result<Vec<DetectedPackage>> {
        let mut detected = Vec::new();
        let json: Value = serde_json::from_str(content)?;
        
        // Check for npm v1 format (dependencies at root)
        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            self.check_npm_dependencies(deps, &mut detected, "");
        }
        
        // Check for npm v2/v3 format (packages object)
        if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
            for (package_path, package_info) in packages {
                // Extract package name from path (e.g., "node_modules/chalk" -> "chalk")
                if let Some(name) = package_path.strip_prefix("node_modules/") {
                    let package_name = name.split('/').next().unwrap_or("");
                    
                    let version = package_info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    
                    let key = format!("{}@{}", package_name, version);
                    if self.compromised_packages.contains_key(&key) {
                        detected.push(DetectedPackage {
                            name: package_name.to_string(),
                            version: version.to_string(),
                            path: package_path.clone(),
                            location: "direct or transitive dependency".to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(detected)
    }
    
    fn check_npm_dependencies(
        &self,
        deps: &serde_json::Map<String, Value>,
        detected: &mut Vec<DetectedPackage>,
        parent_path: &str,
    ) {
        for (name, info) in deps {
            let version = info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            
            let key = format!("{}@{}", name, version);
            if self.compromised_packages.contains_key(&key) {
                let path = if parent_path.is_empty() {
                    name.clone()
                } else {
                    format!("{} > {}", parent_path, name)
                };
                
                let location = if parent_path.is_empty() {
                    "direct dependency"
                } else {
                    "transitive dependency"
                };
                
                detected.push(DetectedPackage {
                    name: name.clone(),
                    version: version.to_string(),
                    path,
                    location: location.to_string(),
                });
            }
            
            // Recursively check nested dependencies
            if let Some(nested_deps) = info.get("dependencies").and_then(|d| d.as_object()) {
                let new_path = if parent_path.is_empty() {
                    name.clone()
                } else {
                    format!("{} > {}", parent_path, name)
                };
                self.check_npm_dependencies(nested_deps, detected, &new_path);
            }
        }
    }
    
    fn parse_yarn_lockfile(&self, content: &str) -> Result<Vec<DetectedPackage>> {
        let mut detected = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i];
            
            // Look for package declarations (e.g., "chalk@^2.0.0:")
            if !line.starts_with(' ') && line.contains('@') {
                // Extract package name
                let package_name = if let Some(idx) = line.find('@') {
                    let name = &line[..idx];
                    // Remove quotes if present
                    name.trim_matches('"').trim_matches('\'')
                } else {
                    ""
                };
                
                // Look for version in the next few lines
                let mut version = "unknown".to_string();
                for j in (i + 1)..lines.len().min(i + 10) {
                    if lines[j].trim().starts_with("version") {
                        if let Some(v) = lines[j].split('"').nth(1) {
                            version = v.to_string();
                            break;
                        }
                    }
                    // Stop if we hit another package declaration
                    if !lines[j].starts_with(' ') {
                        break;
                    }
                }
                
                let key = format!("{}@{}", package_name, version);
                if self.compromised_packages.contains_key(&key) {
                    detected.push(DetectedPackage {
                        name: package_name.to_string(),
                        version,
                        path: package_name.to_string(),
                        location: "yarn dependency".to_string(),
                    });
                }
            }
            
            i += 1;
        }
        
        Ok(detected)
    }
    
    fn parse_pnpm_lockfile(&self, content: &str) -> Result<Vec<DetectedPackage>> {
        let mut detected = Vec::new();
        
        // Try to parse as YAML
        match serde_yaml::from_str::<PnpmLockfile>(content) {
            Ok(lockfile) => {
                // Check direct dependencies
                if let Some(deps) = lockfile.dependencies {
                    for (name, version_info) in deps {
                        let version = match version_info {
                            PnpmDependencyVersion::String(v) => v,
                            PnpmDependencyVersion::Object(obj) => obj.version,
                        };
                        
                        let key = format!("{}@{}", name, version);
                        if self.compromised_packages.contains_key(&key) {
                            detected.push(DetectedPackage {
                                name: name.clone(),
                                version,
                                path: name.clone(),
                                location: "direct dependency".to_string(),
                            });
                        }
                    }
                }
                
                // Check packages section
                if let Some(packages) = lockfile.packages {
                    for (package_spec, _) in packages {
                        // Extract package name from spec (e.g., "/chalk/2.4.2" -> "chalk")
                        let parts: Vec<&str> = package_spec.trim_start_matches('/').split('/').collect();
                        if !parts.is_empty() {
                            let package_name = parts[0];
                            let version = if parts.len() > 1 {
                                parts[1].to_string()
                            } else {
                                "unknown".to_string()
                            };
                            
                            let key = format!("{}@{}", package_name, version);
                            if self.compromised_packages.contains_key(&key) {
                                detected.push(DetectedPackage {
                                    name: package_name.to_string(),
                                    version,
                                    path: package_spec.clone(),
                                    location: "pnpm package".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Fallback to line-by-line parsing if YAML parsing fails
                detected = self.parse_pnpm_lockfile_fallback(content)?;
            }
        }
        
        Ok(detected)
    }
    
    fn parse_pnpm_lockfile_fallback(&self, content: &str) -> Result<Vec<DetectedPackage>> {
        let mut detected = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut in_dependencies = false;
        let mut in_packages = false;
        
        for line in lines {
            // Check section markers
            if line == "dependencies:" {
                in_dependencies = true;
                in_packages = false;
                continue;
            } else if line == "packages:" {
                in_packages = true;
                in_dependencies = false;
                continue;
            } else if !line.starts_with(' ') && !line.is_empty() {
                in_dependencies = false;
                in_packages = false;
            }
            
            // Parse dependencies section
            if in_dependencies && line.starts_with("  ") && !line.starts_with("    ") {
                if let Some(colon_idx) = line.find(':') {
                    let package_name = line[..colon_idx].trim();
                    let version_part = &line[colon_idx + 1..].trim();
                    let version = version_part.trim_matches('\'').trim_matches('"');
                    
                    let key = format!("{}@{}", package_name, version);
                    if self.compromised_packages.contains_key(&key) {
                        detected.push(DetectedPackage {
                            name: package_name.to_string(),
                            version: version.to_string(),
                            path: package_name.to_string(),
                            location: "direct dependency".to_string(),
                        });
                    }
                }
            }
            
            // Parse packages section
            if in_packages && line.starts_with("  /") {
                // Format: "  /package-name@version:"
                if let Some(at_idx) = line.find('@') {
                    if let Some(colon_idx) = line.find(':') {
                        let package_name = line[3..at_idx].trim();
                        let version = line[at_idx + 1..colon_idx].trim();
                        
                        let key = format!("{}@{}", package_name, version);
                        if self.compromised_packages.contains_key(&key) {
                            detected.push(DetectedPackage {
                                name: package_name.to_string(),
                                version: version.to_string(),
                                path: format!("/{}@{}", package_name, version),
                                location: "pnpm package".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(detected)
    }
    
    fn print_results(&self) {
        if self.args.format == "json" {
            let json = serde_json::to_string_pretty(&self.results).unwrap();
            println!("{}", json);
            return;
        }
        
        // Text output with colors
        println!("\n{}", "=".repeat(80));
        println!("{}", "SCAN COMPLETE".blue().bold());
        println!("{}", "=".repeat(80));
        
        println!("\n{} {}", "Files scanned:".cyan(), self.results.scanned_files);
        
        if self.results.findings.is_empty() {
            println!("\n{}", "✓ No compromised packages detected!".green());
        } else {
            println!("\n{}", "⚠ WARNING: Compromised packages detected!".red().bold());
            println!("{}", "These packages were compromised with malware that steals cryptocurrency.".yellow());
            println!("{}", "The attack occurred on September 8th, 2024.".yellow());
            
            for finding in &self.results.findings {
                println!("\n{} {}", "File:".magenta(), finding.file.display());
                println!("{} {} lockfile", "Type:".magenta(), finding.lockfile_type);
                println!("{}", "Compromised packages found:".red());
                
                for pkg in &finding.packages {
                    let key = format!("{}@{}", pkg.name, pkg.version);
                    let downloads = &self.compromised_packages[&key].weekly_downloads;
                    println!("  {} {}@{}", "●".red(), pkg.name.bold(), pkg.version);
                    println!("    Location: {}", pkg.location);
                    println!("    Weekly downloads: {}", downloads);
                    if pkg.path != pkg.name {
                        println!("    Dependency path: {}", pkg.path);
                    }
                }
            }
            
            println!("\n{}", "RECOMMENDED ACTIONS:".yellow().bold());
            println!("1. Update all compromised packages immediately");
            println!("2. Run: npm update or yarn upgrade or pnpm update");
            println!("3. Clear your npm cache: npm cache clean --force");
            println!("4. Regenerate lockfiles after updating");
            println!("5. Check for any suspicious wallet transactions");
            println!("6. Rotate any potentially exposed credentials");
            println!("\n{} https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised", "More info:".cyan());
        }
        
        if !self.results.errors.is_empty() {
            println!("\n{}", "Errors encountered during scan:".yellow());
            for error in &self.results.errors {
                println!("  {} {}", "●".red(), error);
            }
        }
        
        println!("\n{}\n", "=".repeat(80));
    }
    
    fn run(&mut self) -> Result<()> {
        let dir = PathBuf::from(&self.args.directory);
        
        if !dir.exists() {
            eprintln!("{} Directory does not exist: {}", "Error:".red(), dir.display());
            process::exit(1);
        }
        
        if !dir.is_dir() {
            eprintln!("{} Not a directory: {}", "Error:".red(), dir.display());
            process::exit(1);
        }
        
        if self.args.no_color {
            colored::control::set_override(false);
        }
        
        if self.args.format.as_str() == "text" {
            println!("{}", "NPM Compromised Package Scanner".blue().bold());
            println!("{} {}", "Scanning directory:".cyan(), dir.display());
            println!("{} package-lock.json, yarn.lock, pnpm-lock.yaml files", "Looking for:".cyan());
            println!("{}", "=".repeat(80));
        }
        
        self.scan_directory(&dir)?;
        self.print_results();
        
        // Exit with error code if compromised packages were found
        if !self.results.findings.is_empty() {
            process::exit(1);
        }
        
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut scanner = Scanner::new(args);
    scanner.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compromised_packages_list() {
        let args = Args {
            directory: ".".to_string(),
            format: "text".to_string(),
            no_color: false,
            verbose: false,
        };
        let scanner = Scanner::new(args);
        
        assert_eq!(scanner.compromised_packages.len(), 18);
        assert!(scanner.compromised_packages.contains_key("chalk"));
        assert!(scanner.compromised_packages.contains_key("debug"));
        assert!(scanner.compromised_packages.contains_key("ansi-styles"));
    }
    
    #[test]
    fn test_is_lockfile() {
        let args = Args {
            directory: ".".to_string(),
            format: "text".to_string(),
            no_color: false,
            verbose: false,
        };
        let scanner = Scanner::new(args);
        
        assert!(scanner.is_lockfile("package-lock.json"));
        assert!(scanner.is_lockfile("yarn.lock"));
        assert!(scanner.is_lockfile("pnpm-lock.yaml"));
        assert!(scanner.is_lockfile("pnpm-lock.yml"));
        assert!(!scanner.is_lockfile("package.json"));
        assert!(!scanner.is_lockfile("README.md"));
    }
}
