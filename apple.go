package grootstore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// This file contains all functions related to downloading the Apple root store.
// Only works on Unix systems.

var (
	APPLE_ROOT_STORE       = ROOT_FOLDER + "AppleRoot.pem"
	APPLE_DIRECTORY        = ROOT_FOLDER + "apple/"
	APPLE_UNPACKED_DIR     = APPLE_DIRECTORY + "security_certificates-security_certificates-" + APPLE_SECURITY_VERSION
	APPLE_ROOTS_DIRECTORY  = APPLE_UNPACKED_DIR + "/certificates/roots/"
	APPLE_SECURITY_VERSION = "55246.140.2"
	APPLE_ROOT_URL         = "https://github.com/apple-oss-distributions/security_certificates/archive/refs/tags/security_certificates-" + APPLE_SECURITY_VERSION + ".tar.gz"
)

// Downloads Apple's root store, stores it as a PEM file in APPLE_ROOT_STORE
// and returns *x509.CertPool of the root store.
func UpdateAppleRootStore() (*x509.CertPool, error) {
	fmt.Print("Attempting to download Apple root store... ")
	if !fileExists(APPLE_ROOT_STORE) {
		err := downloadAppleRootStore()
		if err != nil {
			return nil, err
		}
		fmt.Print("Apple downloaded successfully!\n")
		err = removeUnusedAppleDirectories()
		if err != nil {
			return nil, err
		}
		err = createAppleRootStorePEM()
		if err != nil {
			return nil, err
		}
	}

	certPool, err := getCertPoolFromAppleFile()
	if err != nil {
		return nil, err
	}

	return certPool, err
}

// Returns Apple's root store *x509.CertPool.
//
// This requires that APPLE_ROOT_STORE is present and won't attempt to download
// the root store if it is missing.
func GetAppleRootStore() (*x509.CertPool, error) {
	certPool, err := getCertPoolFromAppleFile()
	if err != nil {
		return nil, err
	}

	return certPool, nil
}

// Downloads Apple tarball with root store and extracts contents to APPLE_DIRECTORY.
func downloadAppleRootStore() error {

	os.RemoveAll(APPLE_DIRECTORY)

	resp, err := http.Get(APPLE_ROOT_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d. attempting re-download", resp.StatusCode)
	}

	// Stole all of this from https://medium.com/@skdomino/taring-untaring-files-in-go-6b07cf56bc07
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {
		case err == io.EOF:
			return nil

		case err != nil:
			return err

		case header == nil:
			continue
		}

		target := filepath.Join(APPLE_DIRECTORY, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return nil
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
}

// Creates the APPLE_ROOT_STORE PEM file from directory with root store PEM files.
func createAppleRootStorePEM() error {
	ROOTS_DIR := APPLE_DIRECTORY + "roots/"
	files, err := ioutil.ReadDir(ROOTS_DIR)
	if err != nil {
		return err
	}

	appleRootStore, err := os.Create(APPLE_ROOT_STORE)
	if err != nil {
		return err
	}

	for _, fileName := range files {
		file, err := ioutil.ReadFile(ROOTS_DIR + fileName.Name())
		if err != nil {
			return err
		}
		if strings.Contains(fileName.Name(), ".cvsignore") {
			continue
		}
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: file,
		}
		err = pem.Encode(appleRootStore, block)
		if err != nil {
			fmt.Printf(err.Error())
			continue
		}
	}

	// When we are finished, we can delete all raw certificate files.
	err = os.RemoveAll(APPLE_DIRECTORY)
	if err != nil {
		return err
	}
	return nil
}

// Cleans up directories after downloading/unpacking Apple rootstore tarball.
func removeUnusedAppleDirectories() error {
	directory, err := os.Open(APPLE_UNPACKED_DIR)
	if err != nil {
		return err
	}
	defer directory.Close()

	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}

	// Remove all directories that aren't needed
	for _, name := range names {
		if name != "certificates" {
			err = os.RemoveAll(filepath.Join(APPLE_UNPACKED_DIR, name))
			if err != nil {
				return err
			}
		}
	}

	// Lastly, we do some cleanup by moving/removing directories
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	arg0 := "mv"
	arg1 := APPLE_ROOTS_DIRECTORY
	arg2 := APPLE_DIRECTORY

	cmd := exec.Command(arg0, arg1, arg2)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return err
	}

	err = os.RemoveAll(APPLE_DIRECTORY + "security_certificates-" + APPLE_SECURITY_VERSION)
	if err != nil {
		return err
	}

	return nil
}

// Parses APPLE_ROOT_STORE and returns a *x509.CertPool.
func getCertPoolFromAppleFile() (*x509.CertPool, error) {
	file, err := ioutil.ReadFile(APPLE_ROOT_STORE)
	if err != nil {
		return nil, err
	}

	tlsCertificates := getTlsCert(string(file))
	appleRootStore := x509.NewCertPool()

	for _, tlsCertificate := range tlsCertificates.Certificate {
		x509Cert, err := x509.ParseCertificate(tlsCertificate)
		if err != nil {
			return nil, err
		}
		appleRootStore.AddCert(x509Cert)
	}
	return appleRootStore, nil
}
