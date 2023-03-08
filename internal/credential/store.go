package credential

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/credentials"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Store provides credential CRUD operations.
type Store struct {
	configs []*configfile.ConfigFile
}

// NewStore generates a store based on the passed in config file path.
func NewStore(configPaths ...string) (*Store, error) {
	if len(configPaths) == 0 {
		// No config path passed, load default docker config file.
		cfg, err := config.Load(config.Dir())
		if err != nil {
			return nil, err
		}
		if !cfg.ContainsAuth() {
			cfg.CredentialsStore = credentials.DetectDefaultStore(cfg.CredentialsStore)
		}

		return &Store{
			configs: []*configfile.ConfigFile{cfg},
		}, nil
	}

	var configs []*configfile.ConfigFile
	for _, path := range configPaths {
		cfg, err := loadConfigFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		configs = append(configs, cfg)
	}

	return &Store{
		configs: configs,
	}, nil
}

// loadConfigFile reads the credential-related configurationfrom the given path.
func loadConfigFile(path string) (*configfile.ConfigFile, error) {
	var cfg *configfile.ConfigFile
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			cfg = configfile.New(path)
		} else {
			return nil, err
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		cfg = configfile.New(path)
		if err := cfg.LoadFromReader(file); err != nil {
			return nil, err
		}
	}

	if !cfg.ContainsAuth() {
		cfg.CredentialsStore = credentials.DetectDefaultStore(cfg.CredentialsStore)
	}
	return cfg, nil
}

// Credential iterates all the config files, returns the first non-empty
// credential in a best-effort way.
func (s *Store) Credential(ctx context.Context, registry string) (auth.Credential, error) {
	for _, c := range s.configs {
		authConf, err := c.GetCredentialsStore(registry).Get(registry)
		if err != nil {
			return auth.EmptyCredential, err
		}
		cred := auth.Credential{
			Username:     authConf.Username,
			Password:     authConf.Password,
			AccessToken:  authConf.RegistryToken,
			RefreshToken: authConf.IdentityToken,
		}
		if cred != auth.EmptyCredential {
			return cred, nil
		}
	}
	return auth.EmptyCredential, nil
}
