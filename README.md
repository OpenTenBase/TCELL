## Introduction

TCELL is a lightweight, open-source dynamic measurement module based on Trusted Computing. It was co-developed through a joint research initiative between the Beijing Municipal Key Laboratory of Trusted Computing at Beijing University of Technology and the Tencent TDSQL Team.

Designed to provide runtime integrity measurement for databases and critical cloud-native components, TCELL ensures that essential software remains "measurable and auditable" throughout its operation via continuous monitoring, collection, and verification, thereby securing a trusted database environment. In 2026, the project was officially donated to the OpenAtom Foundation's OpenTenBase Community for incubation.

The system leverages Linux kernel module technology and the SM3 cryptographic algorithm (National Standard of China) to build a unified memory anti-tamper framework for critical database components. By utilizing the framework's periodic memory region scanning and dynamic baseline comparison mechanisms, users can monitor and detect advanced threats—such as code injection and memory tampering—in real-time without interrupting business operations.

TCELL specifically addresses the challenge of fileless attacks at runtime within database systems. By providing kernel-level trusted security assurance, it bridges the gap where traditional static file integrity checks fail to cover runtime memory states, effectively enhancing the endogenous security capabilities of databases in complex environments.

## Directory Structure

* **`dynamic_baselib/`**: Core baseline library module.
  * Maintains a Red-Black Tree-based in-memory database that stores process PIDs and the hash baselines of their corresponding code segments and dynamic libraries.
  * Exports kernel symbols (APIs) for the measurement module to call (Register, Verify, Remove).
  * Uses `kprobe` to hook `do_exit`, automatically cleaning up corresponding baseline data when a process exits.
  * Provides a `debugfs` interface for debugging.


* **`dynamic_measure/`**: Measurement scanning module.
  * Starts a kernel thread (`kmeasure_scanner`).
  * **Initial Scan**: Traverses system database-related processes to establish initial baselines.
  * **Periodic Scan**: Polls processes at set intervals (default 30s), calculating the SM3 measurement values of their code segments and linked libraries.
  * **Disposal Logic**: If a measurement value does not match the baseline, it is treated as an integrity violation.


* **`encryption/`**: Encryption algorithm library.
  * Contains the kernel-space implementation of the SM3 hash algorithm.


* **`include/`**: Common header files.
  * Defines data structures, macros, and cross-module API interfaces.



## Features

* **Runtime Dynamic Measurement**: Does not rely on disk file verification; reads memory pages (Page) directly to calculate hashes, enabling detection of **Fileless Attacks** or memory modifications.
* **National Standard SM3 Algorithm**: Adopts the autonomous and controllable SM3 digest algorithm to ensure data uniqueness.
* **Lifecycle Management**: Automatically monitors process creation (initial scan registration) and exit (automatic baseline cleanup) without manual intervention.
* **Active Defense**: Real-time alerts when tampering is detected.
* **Debug Interface**: Supports viewing the current status of the baseline library via `/sys/kernel/debug/baseline_db/`.

## Build & Run

### Environment Requirements

* **Linux Kernel**: Recommended 5.4 and above.
  * 5.4 (Ubuntu 18.04 LTS, etc.) to 6.8 (Ubuntu 22.04 LTS, etc.).
  * The code includes compatibility handling for the Kernel 5.8+ `mmap_read_lock` API changes.
  * Corresponding kernel headers must be installed (`linux-headers-$(uname -r)`).


* **GCC**: Recommended **7.5.0 and above**.
  * Note: The GCC version used to compile the kernel module should be consistent with the GCC version used to compile the currently running kernel (check via `cat /proc/version`).


* **Make**: GNU Make 3.81 and above.

### Build

Execute the following command in the project root directory (or separate subdirectories):

```bash
# Compile dynamic_baselib and dynamic_measure
make

```

Upon successful compilation:

`dynamic_baselib/` directory will generate `dynamic_baselib.ko`

`dynamic_measure/` directory will generate `measure.ko`

### Load Modules

**Note**: Strict loading order must be observed, as `measure.ko` depends on symbols exported by `dynamic_baselib.ko`.

1. **Load Baseline Library Module**
```bash
sudo insmod dynamic_baselib/dynamic_baselib.ko

```


*After successful loading, a debug interface will be created at `/sys/kernel/debug/baseline_db/`.*
2. **Load Measurement Module**
```bash
# Default scan interval is 30 seconds
sudo insmod dynamic_measure/measure.ko

# Or specify a scan interval (e.g., 10 seconds)
sudo insmod dynamic_measure/measure.ko scan_interval_sec=10

```


*Once loaded, the kernel log (`dmesg`) will show the initial scanning progress.*

### Unload Modules

The unloading order is the reverse of loading:

```bash
sudo rmmod measure
sudo rmmod dynamic_baselib

```

## Debugging

After loading `dynamic_baselib`, you can view the internal state using `debugfs`:

```bash
# View currently registered process baselines
sudo cat /sys/kernel/debug/baseline_db/dump

```

## Disclaimer

1. **Forced Termination Risk**: In the current version, the `dynamic_measure` module **does not directly send a SIGKILL signal** to terminate the process when a hash mismatch is detected. Before deploying in a production environment, please be sure to evaluate the business impact. It is recommended to verify in a test environment first before deciding whether to enable active termination features in the future.
2. **Performance Impact**: Frequent full-memory hash calculations consume a certain amount of CPU resources. It is recommended to adjust the `scan_interval_sec` parameter according to the actual load.
