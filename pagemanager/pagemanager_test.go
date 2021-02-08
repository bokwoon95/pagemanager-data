package pagemanager

import (
	"fmt"
	"testing"
)

func Test_LocateDataFolder(t *testing.T) {
	folder, err := LocateDataFolder()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(folder)
}

func Test_New(t *testing.T) {
	pm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", pm)
}
