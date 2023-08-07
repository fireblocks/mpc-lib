# Fireblocks-MPC

This repository contains Fireblocks' C++ implementation of Secure Multi Party Computation (MPC) algorithms for digital signatures. Covered algorithms include [MPC CMP](https://eprint.iacr.org/2020/492) for ECDSA signatures (online and offline variants), online EdDSA signatures and offline asymmetric EdDSA.

It takes the form of a library (`libcosigner`) containing the algorithms and supporting cryptographic routines, as well as an extensive test suite also serving as an integration example.

## Quick Start

### Prerequisites

This version of the code targets *Ubuntu Linux 20.04 LTS* release.
The libraries and headers of the following dependencies are required:

* OpenSSL version 1.1.1
* libuuid (for tests)
* libsecp256k1 (for tests, optional)

All required dependencies can be installed with the command:
```sh
apt install build-essential libssl-dev uuid-dev libsecp256k1-dev
```

### Building and Testing

Build the library and tests by running:
```sh
make
```

To execute the test suite, run the command:
```sh
make run-tests
```

## Usage

A few examples for running a full signing process can be found in the [tests section](https://github.com/fireblocks/mpc-lib/tree/main/test/cosigner)

## Security

Please see our dedicated [security policy](SECURITY.md) page.

## Contributing

Contributions of code and ideas are welcome. Prior to opening a pull request, please carefully review our [contribution guidelines](CONTRIBUTING.md).

## License

The code in this repository is offered under the terms of the GNU General Public License, as described in the [LICENSE](LICENSE) file.
