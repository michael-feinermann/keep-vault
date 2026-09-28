// Test-only independent oracle. BSD-3-Clause golang.org/x/crypto is pinned in go.mod/go.sum.
package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
    "golang.org/x/crypto/chacha20poly1305"
)
type request struct { Key, Nonce, Aad, Plaintext []byte }
type response struct { Combined []byte; Error string }
func main() {
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 65536), 32*1024*1024)
    encoder := json.NewEncoder(os.Stdout)
    for scanner.Scan() {
        var r request
        if err := json.Unmarshal(scanner.Bytes(), &r); err != nil { panic(err) }
        aead, err := chacha20poly1305.NewX(r.Key)
        if err != nil { _ = encoder.Encode(response{Error: err.Error()}); continue }
        combined := aead.Seal(nil, r.Nonce, r.Plaintext, r.Aad)
        if _, err = aead.Open(nil, r.Nonce, combined, r.Aad); err != nil { panic(err) }
        if err = encoder.Encode(response{Combined: combined}); err != nil { panic(err) }
    }
    if err := scanner.Err(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
