// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/MaxGridasoff/fail2ban/pkg/chain"
	"github.com/MaxGridasoff/fail2ban/pkg/data"
	"github.com/MaxGridasoff/fail2ban/pkg/ipchecking"
)

type deny struct {
	list ipchecking.NetIPs
	all  bool
}

func New(ipList []string) (*deny, error) {
	var err error

	all := false
	list := make(ipchecking.NetIPs, 0)

	if len(ipList) == 1 && ipList[0] == "*" {
		all = true

		fmt.Println("FUX")
	} else {
		list, err = ipchecking.ParseNetIPs(ipList)
		if err != nil {
			return nil, fmt.Errorf("failed to create new net ips: %w", err)
		}
	}

	return &deny{list: list, all: all}, nil
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	fmt.Printf("data: %+v", data)

	if d.all {
		fmt.Printf("IP %s is denied !!", data.RemoteIP)

		return &chain.Status{Return: true}, nil
	}

	if d.list.Contains(data.RemoteIP) {
		fmt.Printf("IP %s is denied !!", data.RemoteIP)

		return &chain.Status{Return: true}, nil
	}

	fmt.Printf("IP %s not is denied !!!", data.RemoteIP)

	return nil, nil
}
