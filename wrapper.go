package main

import (
    "bytes"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
)

func main() {
    // This wrapper is only for Linux - detect musl vs glibc
    if runtime.GOOS != "linux" {
        fmt.Fprintf(os.Stderr, "This wrapper is only for Linux systems\n")
        os.Exit(1)
    }

    var bin string
    // Detect musl vs glibc with multiple methods
    isMusl := false
    
    // Method 1: Check ldd --version output (ignore exit status)
    out, _ := exec.Command("ldd", "--version").CombinedOutput()
    if bytes.Contains(out, []byte("musl")) {
        isMusl = true
    }
    
    // Method 2: Check if musl-specific file exists
    if !isMusl {
        if _, err := os.Stat("/lib/ld-musl-x86_64.so.1"); err == nil {
            isMusl = true
        }
    }
    
    // Method 3: Check getconf GNU_LIBC_VERSION (only works on glibc)
    if !isMusl {
        out, err := exec.Command("getconf", "GNU_LIBC_VERSION").CombinedOutput()
        if err != nil || len(out) == 0 {
            // If getconf fails or returns empty, likely musl
            isMusl = true
        }
    }
    
    if isMusl {
        bin = "trivy-gitlab-codequality-musl"
    } else {
        bin = "trivy-gitlab-codequality-glibc"
    }

    // Find binary in same directory as wrapper
    exePath, _ := os.Executable()
    binPath := filepath.Join(filepath.Dir(exePath), bin)

    // Pass all arguments to the binary
    cmd := exec.Command(binPath, os.Args[1:]...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Stdin = os.Stdin

    if err := cmd.Run(); err != nil {
        fmt.Fprintf(os.Stderr, "Error running binary: %v\n", err)
        os.Exit(1)
    }
}