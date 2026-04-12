# Fireblocks-MPC

This repository contains Fireblocks' C++ implementation of Secure Multi Party Computation (MPC) algorithms for digital signatures. Covered algorithms include [MPC CMP](https://eprint.iacr.org/2020/492) for ECDSA signatures (online and offline variants), online EdDSA signatures and offline asymmetric EdDSA.

It takes the form of a library (`libcosigner`) containing the algorithms and supporting cryptographic routines, as well as an extensive test suite also serving as an integration example.

## Quick Start

### Prerequisites

This version of the code targets *Ubuntu Linux 20.04 LTS* release.
The libraries and headers of the following dependencies are required:

* OpenSSL version 1.1.1 or higher
* libuuid (for tests)
* libsecp256k1 (for tests, optional)

All required dependencies can be installed with the command:
```sh
apt install build-essential libssl-dev uuid-dev libsecp256k1-dev
```

### Building and Testing

Build the library and tests by running:
```sh
mkdir build; cd build; cmake ..; make
```

To execute the test suite, run the command from the same build folder:
```sh
make test
```

### Benchmarks and Profiling

Build the BAM signing benchmark by enabling the benchmark option during configuration:
```sh
cmake -S . -B build -DMPC_LIB_BUILD_BENCHMARKS=ON
cmake --build build --target bam_sign_benchmark
```

Run the benchmark executable to measure `bam_key_sign` throughput (use `--benchmark_filter` to focus on a specific algorithm):
```sh
./build/benchmarks/bam_sign_benchmark --benchmark_filter=stark
```

To profile the benchmark and visualize the results:
1. Record samples with Linux `perf` (install `hotspot` or another viewer once):
   ```sh
   perf record -F 999 -g ./build/benchmarks/bam_sign_benchmark --benchmark_filter=secp256k1_default
   ```
2. Open the generated `perf.data` in a graphical viewer, e.g.:
   ```sh
   hotspot perf.data        # Qt GUI with flame graphs
   # or convert to Speedscope
   perf script | speedscope
   ```

## Usage

A few examples for running a full signing process can be found in the [tests section](https://github.com/fireblocks/mpc-lib/tree/main/test/cosigner)

## Security

Please see our dedicated [security policy](SECURITY.md) page.

## Contributing

Contributions of code and ideas are welcome. Prior to opening a pull request, please carefully review our [contribution guidelines](CONTRIBUTING.md).

## License

The code in this repository is offered under the terms of the GNU General Public License, as described in the [LICENSE](LICENSE) file.
