
# DEB

![DEB LOGO](https://files.slack.com/files-pri/TQZR8FFK4-F0A1JC6NBDW/gemini_generated_image_m8vwx5m8vwx5m8vw.png?pub_secret=0baa8f9dd6)
*Logo created with [nanobanana](https://github.com/CryptoLabInc/nanobanana)*

DEB is a homomorphic encryption, decryption, and key generation library implementing the CKKS scheme.

## Features

- Secret-key generation and management
- Encryption and decryption operations
- Evaluation(public)-key generation and management
- Serialization support for encrypted objects and keys

## Build

### Quick Start
```sh
cmake --preset release
cmake --build --preset release
```

### Build Options

The project uses CMake presets for configuration. Available presets:

- **release**: Optimized build with `-O3` optimization
- **debug**: Debug build with symbols and no optimization

You can also configure custom builds:

```sh
# Configure with custom options
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON

# Build
cmake --build build

# Install
cmake --build build --target install
```

### CMake Options

- `BUILD_SHARED_LIBS`: Build a shared library instead of a static one. (default: OFF)
- `DEB_BUILD_BENCHMARK`: Build the benchmark suite. (default: OFF)
- `DEB_BUILD_DOXYGEN`: Build the documentation with Doxygen. (default: OFF)
- `DEB_BUILD_EXAMPLES`: Build the example programs. (default: ON)
- `DEB_BUILD_TEST`: Build the test suite. (default: ON)
- `DEB_BUILD_WITH_OMP`: Build with OpenMP support. (default: ON)
- `DEB_INSTALL`: Install the deb library and headers. (default: ON)
- `DEB_INSTALL_ALEA`: Install the alea library when installing deb. (default: OFF)
- `DEB_INSTALL_FLATBUFFERS`: Install the flatbuffers library when installing deb. (default: OFF)
- `DEB_RUNTIME_RESOURCE_CHECK`: Enable runtime resource check. (default: ON)

## Testing

Run all tests:
```sh
ctest --preset all-test
```

Run specific test suites:
```sh
cd build
ctest -R <test_name_pattern>
```

## Examples

The `examples/` directory contains sample programs demonstrating various features of the DEB library:

- **KeyGeneration.cpp**: Demonstrates how to generate secret keys and evaluation keys
  ```sh
  ./build/examples/KeyGeneration
  ```

- **EnDecryption.cpp**: Shows basic encryption and decryption operations with a single secret key
  ```sh
  ./build/examples/EnDecryption
  ```

- **EnDecryption-MultiSecret.cpp**: Demonstrates encryption and decryption with multi-secret parameter
  ```sh
  ./build/examples/EnDecryption-MultiSecret
  ```

- **SeedOnlySecretKey.cpp**: Shows how to generate and use seed-only secret keys for efficient key storage
  ```sh
  ./build/examples/SeedOnlySecretKey
  ```

- **Serialization.cpp**: Demonstrates how to serialize and deserialize encrypted objects and keys
  ```sh
  ./build/examples/Serialization
  ```

All examples are automatically built when `DEB_BUILD_EXAMPLES=ON` (default). Run them from the build directory after building the project.

### License
deb is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions.

See the LICENSE file for more details.

### Contact

juny2400@cryptolab.co.kr
leejonghyeong@cryptolab.co.kr
