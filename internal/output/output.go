package output

type JSONOutput struct {
	Signatures JSONRegistry `json:"registry"`
	Registry   string       `json:"name"`
}

type JSONRegistry struct {
	Entries []JSONSignature `json:"signatures"`
}

type JSONSignature struct {
	Path                string `json:"path"`
	Digest              string `json:"digest"`
	NotaryV2Thumbprints string `json:"thumbprints"`
	CertificateSubject  string `json:"subjectname"`
}
