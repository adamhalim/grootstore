package grootstore

import (
	"errors"

	"github.com/gocolly/colly"
)

const (
	STATUS_INDEX = 0
)

// Scrapes MICROSOFT_URL for crt.sh links. Filters out certs that
// labeled as "Disabled".
func getMicrosoftCRTLinks() ([]string, error) {

	c := colly.NewCollector()
	var urls []string
	c.OnHTML(".dataRow", func(e *colly.HTMLElement) {
		e.ForEach("span", func(i int, h *colly.HTMLElement) {
			if i == STATUS_INDEX {
				if h.Text != "Disabled" {
					// Filter out certificates that are "Disabled"
					urls = append(urls, e.ChildAttr("a", "href"))
				}
			}
		})
	})
	c.Visit(MICROSOFT_URL)
	if len(urls) == 0 {
		return nil, errors.New("no microsoft urls found")
	}
	return urls, nil
}
