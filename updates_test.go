package grootstore

import (
	"testing"
)

// All these tests are kind of awful.
// We should at least check that the files are present
// and that they're not empty.

func TestUpdateNSS(t *testing.T) {
	_, err := UpdateNSSRootStore()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestUppdateApple(t *testing.T) {
	_, err := UpdateAppleRootStore()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestUpdateMicrosoft(t *testing.T) {
	_, err := UpdateMicrosoftRootStore()
	if err != nil {
		t.Errorf(err.Error())
	}
}
