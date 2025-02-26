//go:generate sh -c "go run mkntstatus.go > ntstatus.go && gofmt -w ntstatus.go"

// Package erref provides types and constants for Windows NT status codes as defined in [MS-ERREF].
// It implements error handling functionality for the SMB2 protocol by providing a strongly
// typed NtStatus type and corresponding error codes.
//
// The package includes automatically generated NT status codes and their corresponding string
// representations from the official Microsoft documentation. These status codes are used
// throughout the SMB2 protocol to indicate the success, failure, or other status of operations.
//
// The ntstatus.go file containing the actual status codes and strings is automatically
// generated using the mkntstatus.go tool, which scrapes the official Microsoft documentation
// to ensure accuracy and completeness of the error codes.
//
// For more information about the error codes, see:
// https://msdn.microsoft.com/en-au/library/cc704588.aspx

package erref
