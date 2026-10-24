package control

import "testing"

func TestTheClientWaitsLongerThanAReset(t *testing.T) {
	if httpClient.Timeout <= resetTimeout {
		t.Errorf("the client gives up after %v, before a reset that waits %v for its sessions fails", httpClient.Timeout, resetTimeout)
	}
}
