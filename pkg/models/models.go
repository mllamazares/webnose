package models

type Info struct {
	ID          string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description string   `yaml:"description" json:"description"`
	Author      string   `yaml:"author" json:"author"`
	RiskScore   float64  `yaml:"risk_score" json:"risk_score"`
	Tags        []string `yaml:"tags" json:"tags"`
}

type Matcher struct {
	Type            string   `yaml:"type" json:"type"`
	Part            string   `yaml:"part" json:"part"`
	Regex           []string `yaml:"regex" json:"regex"`
	Negative        bool     `yaml:"negative" json:"negative"`
	CaseInsensitive bool     `yaml:"case_insensitive" json:"case_insensitive"`
}

type Template struct {
	ID       string    `yaml:"id" json:"id"`
	Info     Info      `yaml:"info" json:"info"`
	Matchers []Matcher `yaml:"matchers" json:"matchers"`
}

type SmellResult struct {
	SmellID string `json:"smell_id"`
	Count   int    `json:"count"`
}

type Result struct {
	URL        string                 `json:"url"`
	Subdomain  string                 `json:"subdomain"`
	RiskScore  float64                `json:"risk_score"`
	SmellCount int                    `json:"smell_count"`
	Smells     map[string]int         `json:"smells"`
	Error      string                 `json:"error,omitempty"`
}

type SubdomainStats struct {
	RiskScore   float64 `json:"risk_score"`
	AvgRisk     float64 `json:"avg_risk"`
	MaxRisk     float64 `json:"max_risk"`
	URLCount    int     `json:"url_count"`
	TotalSmells int     `json:"total_smells"`
}

type Report struct {
	Subdomains map[string]SubdomainStats `json:"subdomains"`
	URLs       []Result                  `json:"urls"`
}
