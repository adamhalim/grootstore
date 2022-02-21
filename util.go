package grootstore

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
)

var (
	ROOT_FOLDER = "roots/"
)

// Change where the root store PEM files are stored.
// directory should be a relative filepath.
func SetRootDirectory(directory string) error {
	path, err := os.Getwd()
	if err != nil {
		return err
	}
	_, err = os.Stat(fmt.Sprintf("%s/%s", path, directory))
	if err != nil {
		return err
	}

	ROOT_FOLDER = directory
	if directory[len(directory)-1] != '/' {
		ROOT_FOLDER += "/"
	}
	updatePaths()
	return nil
}

// Update all paths when we change from default.
func updatePaths() {
	NSS_CSV = ROOT_FOLDER + "IncludedCACertificateWithPEMReport.csv"
	NSS_ROOT_STORE = ROOT_FOLDER + "NSSroot.pem"

	MICROSOFT_ROOT_STORE = ROOT_FOLDER + "MSroot.pem"

	APPLE_ROOT_STORE = ROOT_FOLDER + "AppleRoot.pem"
	APPLE_DIRECTORY = ROOT_FOLDER + "apple/"
	APPLE_UNPACKED_DIR = APPLE_DIRECTORY + "security_certificates-" + APPLE_SECURITY_VERSION
	APPLE_ROOTS_DIRECTORY = APPLE_UNPACKED_DIR + "/certificates/roots/"
}

// Generates tls.Certificate from PEM string
func getTlsCert(certInput string) tls.Certificate {
	var cert tls.Certificate
	certPEMBlock := []byte(certInput)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}
