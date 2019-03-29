package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func TestHttpOff(t *testing.T) {
	fmt.Println(strings.Trim(" abc ", " "))
	resp, err := http.Post("http://127.0.0.1:8081/off",
		"text/plain",
		strings.NewReader("1111111111111111"))
	if err != nil {
		fmt.Println(err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(body))

}
