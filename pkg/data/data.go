// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
)

type key string

const contextDataKey key = "data"

type Data struct {
	RemoteIP string
}

func getRemoteAddr(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("failed to split remote address %q: %w", ip, err)
	}

	return ip, nil
}

// ServeHTTP sets data in the request context, to be extracted with GetData.
func ServeHTTP(header string, w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	var err error

	data := &Data{
		RemoteIP: "",
	}

	if len(header) != 0 {
		//TODO: we need to validate IPv4, IPv6 address format.
		data.RemoteIP = r.Header.Get(header)
		if len(data.RemoteIP) == 0 {
			log.Printf("data.ServeHTTP error: %v", fmt.Errorf("failed to find custom header: %s. bypass to RemoteAdder", header))
		}
	}

	if len(data.RemoteIP) == 0 {
		data.RemoteIP, err = getRemoteAddr(r)
		if err != nil {
			return nil, fmt.Errorf("failed to split remote address %q: %w", data.RemoteIP, err)
		}
	}

	return r.WithContext(context.WithValue(r.Context(), contextDataKey, data)), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
