#!/bin/bash

mkdir -p enclave-security-integration/enclave
mkdir -p enclave-security-integration/host

# README.md
cat << EOF > enclave-security-integration/README.md
# Enclave Security Integration

This repository provides a basic integration of secure enclaves using the Open Enclave SDK. Enclaves enable isolated, secure execution of code, protecting sensitive data and operations from the rest of the system.

## Prerequisites

- Install Open Enclave SDK: Follow the [installation guide](https://openenclave.io/sdk/getting-started/install_oe_sdk-Ubuntu_20.04).
- Supported hardware: Intel SGX-enabled CPU or compatible TEE.
- Build tools: CMake, Make, GCC/Clang.

## Building and Running

1. Clone the repo:
   \`\`\`
   git clone https://github.com/yourusername/enclave-security-integration.git
   cd enclave-security-integration
   \`\`\`

2. Build:
   \`\`\`
   mkdir build
   cd build
   cmake ..
   make
   \`\`\`

3. Run:
   \`\`\`
   ./host/enclave_sample
   \`\`\`

## How It Works

- **Host Application**: Creates and interacts with the enclave.
- **Enclave**: Performs secure operations (e.g., encryption) in a trusted environment.
- **Attestation**: The enclave can generate reports to prove its integrity.

Extend this for your platform by adding platform-specific logic in the host and more secure functions in the enclave.

## License

MIT License. See LICENSE file.
EOF

# Makefile
cat << EOF > enclave-security-integration/Makefile
all: build

build:
	mkdir -p build
	cd build && cmake .. && make

clean:
	rm -rf build
EOF

# CMakeLists.txt
cat << EOF > enclave-security-integration/CMakeLists.txt
cmake_minimum_required(VERSION 3.11)

project(enclave_security_integration LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)

add_custom_target(
    sign ALL
    DEPENDS enclave enclave_signed
    COMMENT "Signing the enclave"
)
EOF

# enclave/enclave.c
cat << EOF > enclave-security-integration/enclave/enclave.c
#include <openenclave/enclave.h>
#include <string.h>
#include "enclave_t.h"  // Generated from EDL

// Sample secure function: Encrypt a message using a simple XOR (for demo; use real crypto in production)
oe_result_t secure_encrypt(
    const char* input,
    char* output,
    size_t* output_len)
{
    if (!input || !output || !output_len)
        return OE_INVALID_PARAMETER;

    size_t len = strlen(input);
    if (len >= *output_len)
        return OE_BUFFER_TOO_SMALL;

    for (size_t i = 0; i < len; i++)
    {
        output[i] = input[i] ^ 0xAA;  // Simple XOR encryption
    }
    output[len] = '\0';
    *output_len = len + 1;

    return OE_OK;
}

// ECall entry point
oe_result_t enclave_secure_operation(
    const char* input,
    char* output,
    size_t* output_len)
{
    return secure_encrypt(input, output, output_len);
}
EOF

# enclave/enclave.edl
cat << EOF > enclave-security-integration/enclave/enclave.edl
enclave {
    trusted {
        public oe_result_t enclave_secure_operation(
            [in, string] const char* input,
            [user_check, out, size=*output_len] char* output,
            [in, out] size_t* output_len);
    };
};
EOF

# enclave/enclave.conf
cat << EOF > enclave-security-integration/enclave/enclave.conf
{
  "Debug": 1,
  "ProductID": 1,
  "SecurityVersion": 1,
  "NumHeapPages": 1024,
  "NumStackPages": 4,
  "NumTCS": 1
}
EOF

# host/host.c
cat << EOF > enclave-security-integration/host/host.c
#include <openenclave/host.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/attester.h>
#include <stdio.h>
#include <string.h>
#include "enclave_u.h"  // Generated from EDL

int main(int argc, char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    // Create enclave
    result = oe_create_enclave_security_integration_enclave(
        "./enclave/enclave_signed.so",
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        fprintf(stderr, "Failed to create enclave: %d\\n", result);
        return 1;
    }

    // Call into enclave
    const char* input = "Hello, secure world!";
    char output[256];
    size_t output_len = sizeof(output);

    result = enclave_secure_operation(enclave, input, output, &output_len);

    if (result == OE_OK)
    {
        printf("Input: %s\\n", input);
        printf("Encrypted Output: %s\\n", output);
    }
    else
    {
        fprintf(stderr, "Enclave call failed: %d\\n", result);
    }

    // Optional: Attestation
    // Initialize attester
    oe_attester_initialize();

    // Generate evidence (simplified; add full attestation logic as needed)
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    result = oe_attest_sgx_local(enclave, NULL, 0, &evidence, &evidence_size);
    if (result == OE_OK)
    {
        printf("Attestation evidence generated successfully.\\n");
        free(evidence);
    }

    oe_attester_shutdown();

    // Terminate enclave
    oe_terminate_enclave(enclave);

    return 0;
}
EOF

echo "Setup complete! Directory 'enclave-security-integration' created with all files."