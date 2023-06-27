# Grootstore - Root Store Utilities
Grootstore is a utility that downloads root stores in PEM format. It currently supports downloading the latest Microsoft, Apple and NSS root store.


## Installation
To install, simply run
```
go get github.com/adamhalim/grootstore
```
and import the packageto your project with

```go
import (
    "github.com/adamhalim/grootstore"
)
```

## Usage

To download the latest root store, simply call the corresponding function. For example:

```go
// Downloads NSS root store and stores it in roots/
nssRootStore, err := UpdateNSSRootStore()
if err != nil {
    fmt.Printf("%s\n", err.Error())
}

// Downloads Apple root store and stores it in roots/
appleRootStore, err := UpdateAppleRootStore()
if err != nil {
    fmt.Printf("%s\n", err.Error())
}

// Now we can use the *x509.CertPools for chain validation etc.

```

When the root stores are already saved, we can get them as `*x509.CertPool` directly with 

```go
nssRootStore, _ := GetNSSRootStore()
```

If you simply want to download the latest root stores, you can do so by cloning this repo and running `go test -timeout 5m0s`. The tests in `updates_test.go` will download the latest root stores for NSS, Apple and Microsoft.

### Changing default directory

By default, root stores are stored in `roots/`. To change this, simply call `SetRootDirectory()`

```go
err := SetRootDirectory("data/root_stores/")
if err != nil {
    fmt.Printf("%s\n", err.Error())
}

// Now, the NSS root store will be saved in data/root_stores/ instead of roots/
nssRootStore, err := UpdateNSSRootStore()
if err != nil {
    fmt.Printf("%s\n", err.Error())
}
```

## TODO:

1. More ways of using the root store PEM files, such as getting them as a `[]x509.Certificate` for example.
2. Make it run on all platforms. Currently uses `mv` to move files for Apple roots.