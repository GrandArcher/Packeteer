package rosrest

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestLogin(t *testing.T) {
	env := plugin.Env{Getenv: func(k string) string {
		return map[string]string{"PK_USER": "pk-reader", "PK_PASS": "lab-only"}[k]
	}}
	l, err := Config{URL: "https://192.0.2.254/", UsernameEnv: "PK_USER", PasswordEnv: "PK_PASS"}.Login(env)
	if err != nil {
		t.Fatal(err)
	}
	if l.Base != "https://192.0.2.254/rest" || l.User != "pk-reader" || l.Pass != "lab-only" || l.Transport == nil || l.Transport.TLSClientConfig == nil {
		t.Errorf("login = %+v", l)
	}
	l, err = Config{URL: "http://127.0.0.1:18780", UsernameEnv: "PK_USER", PasswordEnv: "PK_PASS"}.Login(env)
	if err != nil || l.Base != "http://127.0.0.1:18780/rest" || l.Transport.TLSClientConfig != nil {
		t.Errorf("loopback http = %+v, %v", l, err)
	}
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{URL: "http://192.0.2.254", UsernameEnv: "PK_USER", PasswordEnv: "PK_PASS"}, "must be https"},
		{Config{URL: "https://192.0.2.254?x=1", UsernameEnv: "PK_USER", PasswordEnv: "PK_PASS"}, "without credentials or query"},
		{Config{URL: "https://192.0.2.254", UsernameEnv: "PK_USER"}, "username_env and password_env are required"},
		{Config{URL: "https://192.0.2.254", UsernameEnv: "PK_USER", PasswordEnv: "UNSET"}, "UNSET is not set"},
		{Config{URL: "https://192.0.2.254", UsernameEnv: "PK_USER", PasswordEnv: "PK_PASS", CAFile: "ca.pem"}, "absolute path"},
	} {
		if _, err := c.cfg.Login(env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.cfg, err, c.want)
		}
	}
	// The config editor checks a file for a process that may not have the
	// variables yet.
	if _, err := (Config{URL: "https://192.0.2.254", UsernameEnv: "PK_USER", PasswordEnv: "UNSET"}).Login(plugin.Env{CheckOnly: true}); err != nil {
		t.Errorf("check only: %v", err)
	}
}
