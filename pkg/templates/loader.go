package templates

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/mllamazares/webnose/pkg/models"
	"gopkg.in/yaml.v3"
)

func LoadTemplates(dir string, tags []string) ([]models.Template, error) {
	var templates []models.Template
	targetTags := make(map[string]bool)
	for _, t := range tags {
		targetTags[strings.ToLower(strings.TrimSpace(t))] = true
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil // Skip unreadable files
			}

			var tmpl models.Template
			if err := yaml.Unmarshal(data, &tmpl); err != nil {
				return nil // Skip invalid YAML
			}

			// Fallback ID if missing
			if tmpl.ID == "" {
				tmpl.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			}

			// Filter by tags
			if len(targetTags) > 0 {
				matched := false
				for _, t := range tmpl.Info.Tags {
					if targetTags[strings.ToLower(t)] {
						matched = true
						break
					}
				}
				if !matched {
					return nil
				}
			}

			templates = append(templates, tmpl)
		}
		return nil
	})

	return templates, err
}
