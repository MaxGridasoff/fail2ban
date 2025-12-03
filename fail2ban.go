// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/MaxGridasoff/fail2ban/pkg/chain"
	"github.com/MaxGridasoff/fail2ban/pkg/fail2ban"
	f2bHandler "github.com/MaxGridasoff/fail2ban/pkg/fail2ban/handler"
	"github.com/MaxGridasoff/fail2ban/pkg/ipchecking"
	lAllow "github.com/MaxGridasoff/fail2ban/pkg/list/allow"
	lDeny "github.com/MaxGridasoff/fail2ban/pkg/list/deny"
	"github.com/MaxGridasoff/fail2ban/pkg/response/status"
	"github.com/MaxGridasoff/fail2ban/pkg/rules"
	uAllow "github.com/MaxGridasoff/fail2ban/pkg/url/allow"
	uDeny "github.com/MaxGridasoff/fail2ban/pkg/url/deny"
)

func init() {
	log.SetOutput(os.Stdout)
}

// List struct.
type List struct {
	IP    []string
	Files []string
}

// Config struct.
type Config struct {
	Denylist  List   `yaml:"denylist"`
	Allowlist List   `yaml:"allowlist"`
	Header    string `yaml:"header"`

	Rules rules.Rules `yaml:"port"`
}

// CreateConfig populates the Config data object.
func CreateConfig() *Config {
	return &Config{
		Rules: rules.Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
		},
	}
}

// ImportIP extract all ip from config sources.
func ImportIP(list List) ([]string, error) {
	var rlist []string

	for _, ip := range list.Files {
		content, err := os.ReadFile(ip)
		if err != nil {
			return nil, fmt.Errorf("error when getting file content: %w", err)
		}

		rlist = append(rlist, strings.Split(string(content), "\n")...)
		if len(rlist) > 1 {
			rlist = rlist[:len(rlist)-1]
		}
	}

	rlist = append(rlist, list.IP...)

	return rlist, nil
}

// New instantiates and returns the required components used to handle a HTTP
// request.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if !config.Rules.Enabled {
		log.Println("Plugin: FailToBan is disabled")

		return next, nil
	}

	fmt.Printf("allow list: %+v", config.Allowlist)
	allowIPs, err := ImportIP(config.Allowlist)

	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	allowNetIPs, err := ipchecking.ParseNetIPs(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	allowHandler, err := lAllow.New(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
	}

	denyIPs, err := ImportIP(config.Denylist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse denylist IPs: %w", err)
	}

	denyHandler, err := lDeny.New(denyIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
	}

	rules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	log.Println("Plugin: FailToBan is up and running")

	f2b := fail2ban.New(rules, allowNetIPs)

	c := chain.New(
		next,
		strings.TrimSpace(config.Header),
		allowHandler,
		denyHandler,
		uDeny.New(rules.URLRegexpBan, f2b),
		uAllow.New(rules.URLRegexpAllow),
		f2bHandler.New(f2b),
	)

	if rules.StatusCode != "" {
		statusCodeHandler, err := status.New(next, rules.StatusCode, f2b)
		if err != nil {
			return nil, fmt.Errorf("failed to create status handler: %w", err)
		}

		c.WithStatus(statusCodeHandler)
	}

	return c, nil
}
