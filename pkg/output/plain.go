package output

import (
	"encoding/json"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

type Printers struct {
	header *color.Color
	text *color.Color
	data *color.Color
}

var (
	yellowPrinter = color.New(color.FgYellow)
	greenPrinter  = color.New(color.FgHiGreen)
	whitePrinter  = color.New(color.FgWhite)
	faintWhitePrinter = color.New(color.FgWhite, color.Faint)

	faint = Printers{
		header: faintWhitePrinter,
		text:   faintWhitePrinter,
		data:   faintWhitePrinter,
	}

	verified = Printers{
		header: yellowPrinter,
		text:   greenPrinter,
		data:   whitePrinter,
	}

	unverified = Printers{
		header: whitePrinter,
		text:   whitePrinter,
		data:   whitePrinter,
	}
)

func PrintPlainOutput(r *detectors.ResultWithMetadata, faintWhiteOnly bool) {
	out := outputFormat{
		DetectorType: r.Result.DetectorType.String(),
		Verified:     r.Result.Verified,
		MetaData:     r.SourceMetadata,
		Raw:          strings.TrimSpace(string(r.Result.Raw)),
	}

	meta, err := structToMap(out.MetaData.Data)
	if err != nil {
		logrus.WithError(err).Fatal("could not marshal result")
	}

	var verifiedStatus, icon string
	var printers Printers

	if out.Verified {
		printers = verified
		verifiedStatus = "verified"
		icon = ""
	} else {
		printers = unverified
		verifiedStatus = "unverified"
		icon = "❓"
	}

	if faintWhiteOnly {
		printers = faint
	}

	printers.header.Printf("Found %s result 🐷🔑%s\n", verifiedStatus, icon)
	printers.text.Printf("Detector Type: %s\n", out.DetectorType)
	printers.text.Printf("Raw result: %s\n", printers.data.Sprint(out.Raw))

	for _, data := range meta {
		for k, v := range data {
			printers.text.Printf("%s: %v\n", strings.Title(k), v)
		}
	}
	printers.text.Printf("\n")
}

func structToMap(obj interface{}) (m map[string]map[string]interface{}, err error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &m)
	return
}

type outputFormat struct {
	DetectorType string
	Verified     bool
	Raw          string
	*source_metadatapb.MetaData
}
