# Simple Architecture Document bsuppla

---

## bsuppla: Container Supply-Chain Scanner (V1)

### Goal

Statically analyze Docker images **without executing them**, identifying suspicious binaries that may indicate supply-chain attacks.

### Scope

* Input: Docker image exported as `.tar`
* Output: Text report (extensible to JSON via `scan/report.rs`)
* Analysis: per-file detectors covering ELF traits, permissions, credentials, package managers, dual-use tools, startup scripts

### Non-Goals

* No Docker daemon interaction (daemon is optional: skip with `BSUPPLA_SKIP_DOCKER`)
* No runtime behavior analysis
* No malware signatures
* No ML

---

### High-Level Architecture

```
+-------------------------------------------------+
| main.rs: Config::from_args() -> pipeline::run()  |
+------------------------+------------------------+
                         |
                         v
+-------------------------------------------------+
| pipeline.rs (composition root — wires stages)    |
+---+-----------------------------+---------------+
    |                             |
    v                             v
+-------------------------------------------------+
| ingest/ (input)                                 |
| docker.rs    pull + save (daemon contact)       |
| image.rs     manifest.json from image tar       |
| manifest.rs  parse manifest                     |
| layers.rs    verify layers in tar               |
| extract.rs   layers -> filesystem               |
+-------------------------------------------------+
                         |
                         v
+-------------------------------------------------+
| scan/ (analysis)                                |
| scanner.rs walks the fs, builds one             |
|   DetectorRegistry (detectors/) and runs it     |
|   on each file (FileContext from core)          |
| allowlist.rs / baseline.rs filter findings      |
| report.rs    text output + suspicion level      |
+-------------------------------------------------+
                         |
                         v
+-------------------------------------------------+
| detectors/ (the extension surface, top level)   |
| mod.rs = default_registry(): one line per       |
|   signal; PathRule for simple matches,          |
|   Detector impls for content-reading signals    |
| permissions.rs, elf.rs, credentials.rs,         |
| package_managers.rs, risky.rs                   |
+-------------------------------------------------+
```

Support modules: `core.rs` (Severity, Finding, FileContext, Detector,
DetectorRegistry, PathRule — the public extension API), `error.rs`,
`config.rs`. See `docs/DEVELOPMENT.md` for the "add a detector" recipe.

### Design principles

* **Flat**: max one folder of nesting; `detectors/` is a first-class
  top-level folder.
* **Open/closed**: the scanning machinery (`scan/`, `core/`) is closed —
  adding a signal never modifies it. `detectors/` is open — a new signal
  is one new line (PathRule) or one new file + one line. Consumers can
  also compose their own registry purely from `bsuppla::core` +
  `bsuppla::detectors` public API.
* **Single composition root**: only `pipeline.rs` calls across domains.

### Trust Model

* Docker image is **untrusted input**
* Tool must never execute image contents
* Analysis is read-only

---

### Threats Addressed

* Backdoored container images
* Packed or obfuscated binaries
* Hidden executables in unexpected paths
* Leaked credentials and private keys
* Redirected package sources, miners, dual-use tools

---