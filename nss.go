package grootstore

import (
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var (
	NSS_URL        = "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV"
	NSS_CSV        = ROOT_FOLDER + "IncludedCACertificateWithPEMReport.csv"
	NSS_ROOT_STORE = ROOT_FOLDER + "NSSroot.pem"
)

// Downloads Mozilla's root store, stores it as a PEM file in NSS_ROOT_STORE
// and returns *x509.CertPool of the root store.
func UpdateNSSRootStore() (*x509.CertPool, error) {
	fmt.Print("Attempting to download NSS root store... ")
	err := downloadNSSRootStoreCSV()
	if err != nil {
		return nil, err
	}
	fmt.Print("NSS downloaded successfully!\n")
	_, err = createNssPEMFromNssCsv()
	if err != nil {
		return nil, err
	}
	certPool, err := getCertPoolFromNssPEMFile()
	if err != nil {
		return nil, err
	}
	return certPool, err
}

// Returns the NSS root store *x509.CertPool.
//
// This requires that NSS_ROOT_STORE is present and won't attempt to download
// the root store if it is missing.
func GetNSSRootStore() (*x509.CertPool, error) {
	certPool, err := getCertPoolFromNssPEMFile()
	return certPool, err
}

// Downloads the latest NSS root store CSV from Mozilla
// and stores it as NSS_ROOT_STORE
func downloadNSSRootStoreCSV() error {
	NSScsv, err := os.Create(NSS_CSV)
	if err != nil {
		return err
	}
	defer NSScsv.Close()

	// Get the data
	resp, err := http.Get(NSS_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	_, err = io.Copy(NSScsv, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

// Reads the NSS_CSV, takes all PEM columns and writes them to NSS_ROOT_STORE.
//
// This function removes NSS_CSV when finished.
func createNssPEMFromNssCsv() (*os.File, error) {
	NSScsv, err := os.Open(NSS_CSV)
	if err != nil {
		return nil, err
	}
	defer NSScsv.Close()

	lines, err := csv.NewReader(NSScsv).ReadAll()
	if err != nil {
		return nil, err
	}

	var PEMstrings string
	const PEMcolumn = 32
	for index, line := range lines {
		if index == 0 {
			continue
		}
		PEMstrings += strings.ReplaceAll(line[PEMcolumn], "'", "") + "\n"
	}

	// Write string to NSS_ROOT_STORE
	file, err := os.Create(NSS_ROOT_STORE)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	_, err = file.WriteString(PEMstrings)
	if err != nil {
		return nil, err
	}
	err = os.Remove(NSS_CSV)
	if err != nil {
		return nil, err
	}
	return file, err
}

// Parse NSS_ROOT_STORE returns a *x509.CertPool.
func getCertPoolFromNssPEMFile() (*x509.CertPool, error) {
	nssData, err := ioutil.ReadFile(NSS_ROOT_STORE)
	if err != nil {
		return nil, err
	}

	tlsCerts := getTlsCert(string(nssData))
	if tlsCerts.Certificate == nil {
		return nil, errors.New("error decoding pem to tls")
	}

	NSS_ROOT := x509.NewCertPool()
	for _, tlsCert := range tlsCerts.Certificate {
		cert, err := x509.ParseCertificate(tlsCert)
		if err != nil {
			return nil, err
		}
		NSS_ROOT.AddCert(cert)
	}
	return NSS_ROOT, nil
}
