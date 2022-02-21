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
	"time"

	"github.com/cheggaaa/pb/v3"
)

var (
	MICROSOFT_URL        = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT"
	MICROSOFT_ROOT_STORE = ROOT_FOLDER + "MSroot.pem"
)

// Downloads Microsoft's root store, stores it as a PEM file in MICROSOFT_ROOT_STORE
// and returns *x509.CertPool of the root store.
func UpdateMicrosoftRootStore() (*x509.CertPool, error) {
	fmt.Print("Attempting to download Microsoft root store, this will take a while...\n")
	urls, err := getMicrosoftCRTLinks()
	if err != nil {
		return nil, err
	}
	err = downloadMicrosoftCRTtoFile(urls, "", pb.StartNew(len(urls)))
	if err != nil {
		return nil, err
	}
	fmt.Print("Microsoft downloaded successfully!\n")
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
func downloadMicrosoftCRTtoFile(CRTlinks []string, PEMstring string, bar *pb.ProgressBar) error {
	var stringLock sync.Mutex
	var failedLinks []string
	// Download each .crt PEM in parallell and append
	// to PEMstring

	for _, url := range CRTlinks {
		// crt.sh imposes quite a low rate limit. Better to not run this
		// in parallell, and maybe even impose an artificial bottleneck.
		// If we fail to download a certificate, we add it to failedLinks
		// and run the function recursively until we have downloaded everything.
		// Unfortunately, this function takes a long time to complete, but it
		// doesn't need to be run that often (MS updates their root store once a month)
		time.Sleep(2 * time.Second)

		if url == "" {
			// There were some issues with []CRTlinks sometimes having 1
			// empty string which seems to be resolved, but
			// I'll keep this here for now.
			continue
		}
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("bad status: %d\n", resp.StatusCode)
			// When a download fails, we add it to failedLinks
			failedLinks = append(failedLinks, url)
			continue
		}
		PEM, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		tlsCert := getTlsCert(string(PEM))
		if len(tlsCert.Certificate) == 0 {
			fmt.Println(string(PEM))
		}
		stringLock.Lock()
		PEMstring += string(PEM)
		bar.Increment()
		stringLock.Unlock()
	}

	// If we had any failed downloads, we run the function recursively
	// until we succeed with all urls
	if len(failedLinks) != 0 {
		downloadMicrosoftCRTtoFile(failedLinks, PEMstring, bar)
		return nil
	}

	bar.Finish()

	// When all PEMs are downloaded, we store them as a file in MICROSOFT_ROOT_STORE
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
