package grootstore

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const CHROMIUM_ROOT_STORE_URL = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT"

var (
	CHROMIUM_ROOT_STORE = ROOT_FOLDER + "ChromiumRoot.pem"
)

func UpdateChromiumRootStore() (*x509.CertPool, error) {
	fmt.Println("Attempting to download Chromium root store...")
	if !fileExists(CHROMIUM_ROOT_STORE) {
		err := downloadChromiumRootStoreToPEM()
		if err != nil {
			return nil, err
		}
		fmt.Println("Chromium downloaded successfully!")
	}
	certPool, err := getChromiumRootStore()
	if err != nil {
		return nil, err
	}
	return certPool, err
}

func GetChromiumRootStore() (*x509.CertPool, error) {
	certPool, err := getChromiumRootStore()
	if err != nil {
		return nil, err
	}
	return certPool, nil
}

func downloadChromiumRootStoreToPEM() error {
	resp, err := http.Get(CHROMIUM_ROOT_STORE_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	encodedData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var decodedData []byte = make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))
	base64.RawStdEncoding.Decode(decodedData, encodedData)

	dataString := string(decodedData[:])

	BEGIN_CERTIFICATE := "-----BEGIN CERTIFICATE-----"
	END_CERTIFICATE := "-----END CERTIFICATE-----"
	insidePEM := false
	PEMstrings := ""

	scanner := bufio.NewScanner(strings.NewReader(dataString))

	for scanner.Scan() {
		text := scanner.Text()
		if text == BEGIN_CERTIFICATE {
			PEMstrings += text + "\n"
			insidePEM = true
			continue
		}

		if insidePEM {
			if text == END_CERTIFICATE {
				PEMstrings += text + "\n"
				insidePEM = false
				continue
			}
			if insidePEM {
				PEMstrings += text + "\n"
			}
		}
	}

	if PEMstrings == "" {
		return fmt.Errorf("error parsing certificates")
	}

	file, err := os.Create(CHROMIUM_ROOT_STORE)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(PEMstrings)
	if err != nil {
		return err
	}
	return nil
}

func getChromiumRootStore() (*x509.CertPool, error) {
	file, err := ioutil.ReadFile(CHROMIUM_ROOT_STORE)
	if err != nil {
		return nil, err
	}
	tlsCertificates := getTlsCert(string(file))
	chromiumRootStore := x509.NewCertPool()
	for _, tlsCertificate := range tlsCertificates.Certificate {
		x509Cert, err := x509.ParseCertificate(tlsCertificate)
		if err != nil {
			return nil, err
		}
		chromiumRootStore.AddCert(x509Cert)
	}
	return chromiumRootStore, nil
}
