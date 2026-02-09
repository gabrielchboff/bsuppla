
# 📄 Simple Architecture Document bsuppla

---

## bsuppla: Container Supply-Chain Scanner (V1)

### Goal

Statically analyze Docker images **without executing them**, identifying suspicious binaries that may indicate supply-chain attacks.

### Scope

* Input: Docker image exported as `.tar`
* Output: Text or JSON report
* Analysis:

  * ELF file detection
  * Binary entropy analysis
  * Simple heuristic flags

### Non-Goals

* No Docker daemon interaction
* No runtime behavior analysis
* No malware signatures
* No ML

---

### High-Level Architecture

```
+----------------------+
| Docker Image (.tar)  |
+----------+-----------+
           |
           v
+----------------------+
| Image Loader         |
| - Reads tar archive  |
| - Parses manifest    |
+----------+-----------+
           |
           v
+----------------------+
| Layer Extractor      |
| - Extracts layer.tar |
| - Builds filesystem  |
+----------+-----------+
           |
           v
+----------------------+
| Binary Analyzer      |
| - Detects ELF files  |
| - Calculates entropy |
| - Applies heuristics |
+----------+-----------+
           |
           v
+----------------------+
| Report Generator     |
+----------------------+
```

---

### Trust Model

* Docker image is **untrusted input**
* Tool must never execute image contents
* Analysis is read-only

---

### Threats Addressed

* Backdoored container images
* Packed or obfuscated binaries
* Hidden executables in unexpected paths

---
