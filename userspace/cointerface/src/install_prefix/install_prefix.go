package install_prefix

import (
    "os"
    "path/filepath"
)

func GetInstallPrefix() (string, error) {
    ex, err := os.Executable()
    if err != nil {
        return "", err
    }
    return filepath.Dir(filepath.Dir(ex)), nil
}
