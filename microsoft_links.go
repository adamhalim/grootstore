package grootstore

import (
	"errors"

	"github.com/gocolly/colly"
)

const (
	STATUS_INDEX = 0
	SHA1_INDEX   = 3
)

// Scrapes MICROSOFT_URL for crt.sh links. Filters out certs that
// labeled as "Disabled".
func getMicrosoftCRTLinks() ([]string, error) {

	c := colly.NewCollector()
	var fingerprints []string
	c.OnHTML(".dataRow", func(e *colly.HTMLElement) {
		saveCert := false
		e.ForEach("span", func(i int, h *colly.HTMLElement) {
			if i == STATUS_INDEX {
				saveCert = h.Text != "Disabled"
			}
			if saveCert && i == SHA1_INDEX {
				fingerprints = append(fingerprints, h.Text)
			}
		})
	})
	c.Visit(MICROSOFT_LIST_URL)
	if len(fingerprints) == 0 {
		return nil, errors.New("no microsoft urls found")
	}
	return fingerprints, nil
}
