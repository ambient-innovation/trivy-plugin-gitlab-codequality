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
    // Detect musl vs glibc
    out, err := exec.Command("ldd", "--version").CombinedOutput()
    if err == nil && bytes.Contains(out, []byte("musl")) {
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