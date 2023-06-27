package grootstore

// This file contains all functions related to downloading the Microsoft root store.
// It currently has a Node.JS dependency which uses puppeteer & chromium.

import (
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
)

var (
	MICROSOFT_LIST_URL   = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT"
	MICROSOFT_ROOT_STORE = ROOT_FOLDER + "MSroot.pem"
	MICROSOFT_CERTS_URL  = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/"
)

// Downloads Microsoft's root store, stores it as a PEM file in MICROSOFT_ROOT_STORE
// and returns *x509.CertPool of the root store.
func UpdateMicrosoftRootStore() (*x509.CertPool, error) {
	fmt.Println("Attempting to download Microsoft root store...")
	if !fileExists(MICROSOFT_ROOT_STORE) {
		urls, err := getMicrosoftCRTLinks()
		if err != nil {
			return nil, err
		}
		fmt.Printf("Found %d certificates, downloading will take a while...\n", len(urls))
		err = downloadMicrosoftCRTtoFile(urls, "")
		if err != nil {
			return nil, err
		}
		fmt.Print("Microsoft downloaded successfully!\n")
	}

	certPool, err := getMicrosoftRootStore()
	if err != nil {
		return nil, err
	}
	return certPool, err
}

// Returns Microsoft's root store *x509.CertPool.
func GetMicrosoftRootStore() (*x509.CertPool, error) {
	certPool, err := getMicrosoftRootStore()
	if err != nil {
		return nil, err
	}
	return certPool, nil
}

// Downloads all Microsoft root certificates as PEM and stores them
// in MICROSOFT_ROOT_STORE
//
// This function takes an empty PEMstring when run initially.
func downloadMicrosoftCRTtoFile(sha1Fingerprints []string, PEMstring string) error {
	var stringLock sync.Mutex
	var failedFingerprints []string

	for _, fingerprint := range sha1Fingerprints {
		if fingerprint == "" {
			// There were some issues with []CRTlinks sometimes having 1
			// empty string which seems to be resolved, but
			// I'll keep this here for now.
			continue
		}

		resp, err := http.Get(MICROSOFT_CERTS_URL + fingerprint + ".crt")
		if err != nil {
			fmt.Println(err.Error())
			failedFingerprints = append(failedFingerprints, fingerprint)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("bad status: %d\n", resp.StatusCode)
			// When a download fails, we add it to failedFingerprints and try again later
			failedFingerprints = append(failedFingerprints, fingerprint)
			continue
		}
		cert, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		pem := getPEMdata(cert)
		stringLock.Lock()
		PEMstring += pem
		fmt.Print(".")
		stringLock.Unlock()
	}

	// If we had any failed downloads, we run the function recursively
	// until we succeed with all urls
	if len(failedFingerprints) != 0 {
		downloadMicrosoftCRTtoFile(failedFingerprints, PEMstring)
		return nil
	}

	// When all certificates are downloaded, we store them as a file in MICROSOFT_ROOT_STORE
	file, err := os.Create(MICROSOFT_ROOT_STORE)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(PEMstring)
	if err != nil {
		return err
	}
	return nil
}

// Parses MICROSOFT_ROOT_STORE and returns a *x509.CertPool.
func getMicrosoftRootStore() (*x509.CertPool, error) {
	file, err := ioutil.ReadFile(MICROSOFT_ROOT_STORE)
	if err != nil {
		return nil, err
	}
	tlsCertificates := getTlsCert(string(file))
	microsoftRootStore := x509.NewCertPool()

	for _, tlsCertificate := range tlsCertificates.Certificate {
		x509Cert, err := x509.ParseCertificate(tlsCertificate)
		if err != nil {
			return nil, err
		}
		microsoftRootStore.AddCert(x509Cert)
	}
	return microsoftRootStore, nil
}
