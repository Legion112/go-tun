package prefixes

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const maxMindDownloadURL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=zip"

// DownloadGeoLite2CountryPrefixes downloads GeoLite2-Country-CSV and returns country IPv4 prefixes.
func DownloadGeoLite2CountryPrefixes(licenseKey, countryISO string) ([]netip.Prefix, error) {
	if licenseKey == "" {
		return nil, fmt.Errorf("MAXMIND_LICENSE_KEY / -license is required")
	}
	tmp, err := os.MkdirTemp("", "gotun-maxmind-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	url := fmt.Sprintf(maxMindDownloadURL, licenseKey)
	// MaxMind also serves .tar.gz for some editions; try zip via HTTP and detect.
	// For simplicity use the documented zip URL; if site returns tar.gz we handle both.
	archivePath := filepath.Join(tmp, "geo.zip")
	if err := download(url, archivePath); err != nil {
		// fallback tar.gz edition_id
		url = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=tar.gz", licenseKey)
		archivePath = filepath.Join(tmp, "geo.tar.gz")
		if err2 := download(url, archivePath); err2 != nil {
			return nil, fmt.Errorf("download: %v (fallback: %w)", err, err2)
		}
		if err := extractTarGz(archivePath, tmp); err != nil {
			return nil, err
		}
	} else {
		// zip: use unzip via archive - Go stdlib has no zip extract of nested easily;
		// try tar.gz path primarily. If zip, shell out is avoided — use archive/zip.
		if err := extractZip(archivePath, tmp); err != nil {
			return nil, err
		}
	}

	csvDir, err := findCSVDir(tmp)
	if err != nil {
		return nil, err
	}
	return ParseMaxMindCountryDir(csvDir, countryISO)
}

// FetchGeoLite2CountryCSV downloads GeoLite2-Country-CSV, extracts RU (or country) prefixes, writes CIDR list.
func FetchGeoLite2CountryCSV(licenseKey, countryISO, outPath string) error {
	prefs, err := DownloadGeoLite2CountryPrefixes(licenseKey, countryISO)
	if err != nil {
		return err
	}
	return WriteCIDRList(outPath, Collapse(prefs))
}

func download(url, dest string) error {
	resp, err := http.Get(url) //nolint:gosec // user-provided license URL to MaxMind
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func extractTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name) //nolint:gosec
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) && filepath.Clean(target) != filepath.Clean(dest) {
			return fmt.Errorf("illegal path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

func findCSVDir(root string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), "Locations-en.csv") || info.Name() == "GeoLite2-Country-Locations-en.csv" {
			found = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("no Locations-en.csv found under %s", root)
	}
	return found, nil
}
