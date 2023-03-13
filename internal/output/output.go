package output

type RepoJSONOutput struct {
	Signatures RepoJSONRegistry `json:"registry"`
	Registry   string           `json:"name"`
}

type FSJSONOutput struct {
	Signatures FSJSONRegistry `json:"filesystem"`
	FileSystem string         `json:"directories"`
}

type RepoJSONRegistry struct {
	Entries []RepoJSONSignature `json:"signatures"`
}

type FSJSONRegistry struct {
	Entries []FSJSONSignature `json:"signatures"`
}

type RepoJSONSignature struct {
	Path                string `json:"path"`
	Digest              string `json:"digest"`
	NotaryV2Thumbprints string `json:"thumbprints"`
	CertificateSubject  string `json:"subjectname"`
}

type FSJSONSignature struct {
	Path                 string `json:"path"`
	Digest               string `json:"digest"`
	CertificateSubject   string `json:"subjectname"`
	CounterSignerSubject string `json:"countersigner"`
}
