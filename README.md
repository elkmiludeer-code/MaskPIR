# Distributed PIR Protocol Implementation (Go)

## Overview
This project provides a robust implementation of a Private Information Retrieval (PIR) protocol in Go. It integrates Secure Three-party Computation (S3R) for secure comparisons and Paillier homomorphic encryption to ensure that clients can retrieve data from a server's encrypted database without revealing their query conditions.

## Key Functionalities
- **Privacy-Preserving Retrieval**: Clients can query and retrieve specific data rows while keeping the query parameters hidden from the server.
- **Secure Comparison (S3R)**: Implements a secure comparison protocol to determine matching row indices without exposing raw data.
- **Homomorphic Encryption**: Uses Paillier encryption for secure key exchange and data retrieval operations.
- **Database Encryption**: Supports AES-based symmetric encryption for the underlying database, with per-row key management.
- **Distributed Support**: Capable of running in both local and distributed (VM-based) environments.

## Main Files and Structure
- [client.go](file:///d:/Codefield/PIR/go-version/client.go): Core implementation of the PIR client.
- [server.go](file:///d:/Codefield/PIR/go-version/server.go): Core implementation of the PIR server.
- [main_vm.go](file:///d:/Codefield/PIR/go-version/main_vm.go): Entry point for the distributed VM execution mode.
- [core/](file:///d:/Codefield/PIR/go-version/core/): Cryptographic modules including AES, Paillier, and database management.
- [config/](file:///d:/Codefield/PIR/go-version/config/): System configuration and settings.
- [data/data.csv](file:///d:/Codefield/PIR/data/data.csv): Sample dataset used for testing and demonstration.

---
*Note: This project is intended for research and educational purposes.*
