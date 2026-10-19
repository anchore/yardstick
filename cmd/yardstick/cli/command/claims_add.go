package command

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelwrite"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

type claimsAddConfig struct {
	claimsOption  `yaml:",inline" mapstructure:",squash"`
	nameOption    `yaml:",inline" mapstructure:",squash"`
	Gate          string `yaml:"gate" json:"gate" mapstructure:"gate"`
	Subject       string `yaml:"subject" json:"subject" mapstructure:"subject"`
	Package       string `yaml:"package" json:"package" mapstructure:"package"`
	Vulnerability string `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	Verdict       string `yaml:"verdict" json:"verdict" mapstructure:"verdict"`
	Justification string `yaml:"justification" json:"justification" mapstructure:"justification"`
	Note          string `yaml:"note" json:"note" mapstructure:"note"`
	Author        string `yaml:"author" json:"author" mapstructure:"author"`
	Global        bool   `yaml:"global" json:"global" mapstructure:"global"`
}

func (c *claimsAddConfig) AddFlags(flags clio.FlagSet) {
	c.claimsOption.AddFlags(flags)
	c.nameOption.AddFlags(flags)
	flags.StringVarP(&c.Gate, "gate", "", "the gate whose last scan the label is about; seenIn is filled from it")
	flags.StringVarP(&c.Subject, "subject", "", "the gate subject, by name or reference")
	flags.StringVarP(&c.Package, "package", "", "the package, as a purl; a field it does not state matches any value (none: the label is about the image)")
	flags.StringVarP(&c.Vulnerability, "vulnerability", "", "the vulnerability id")
	flags.StringVarP(&c.Verdict, "verdict", "", "tp, fp or unclear")
	flags.StringVarP(&c.Justification, "justification", "", "why, as listed under the verdict in vocabulary.yaml (required for fp and unclear)")
	flags.StringVarP(&c.Note, "note", "", "anything else a reviewer should know")
	flags.StringVarP(&c.Author, "author", "", "who makes the call (default: git config user.name)")
	flags.BoolVarP(&c.Global, "global", "", "the label holds on every subject with the package: written to global/<type>.json")
}

// check fails on a missing flag or a run name that is not one segment, before any gate loads.
func (c *claimsAddConfig) check() error {
	if c.Gate == "" || c.Subject == "" || c.Vulnerability == "" || c.Verdict == "" {
		return errors.New("add needs --gate, --subject, --vulnerability and --verdict")
	}
	return runrecord.CheckName(c.Name)
}

func ClaimsAdd(app clio.Application) *cobra.Command {
	cfg := &claimsAddConfig{nameOption: newNameOption()}
	return app.SetupCommand(&cobra.Command{
		Use:   "add --gate <gate.yaml> --subject <name> --vulnerability <id> --verdict tp|fp|unclear [--package <purl>] [--justification <value>]",
		Short: "Write one label into the gate's last local claims source, filling seenIn from its last scan",
		Long: `add writes one label through the label writer into the last claims source of a gate (the
gate file's own, then --claims), which must be a local directory. The label's seenIn records
what the gate's last scan of the subject used: the unfiltered SBOM's digest, the syft that built
it, and the grype and DB of the setup that reported the match (the candidate's when both or
neither did), so a label that later stops pairing can say why.`,
		Example: `  yardstick claims add --gate gates/deb.yaml --subject deb --package pkg:deb/debian/tar \
    --vulnerability CVE-2005-2541 --verdict fp --justification fix-installed --claims ./.claims`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			author := cfg.Author
			if author == "" {
				author = gitUser()
			}
			log.Debugf("options: name=%s gate=%s subject=%s vulnerability=%s verdict=%s author=%s claims=%v", cfg.Name, cfg.Gate, cfg.Subject, cfg.Vulnerability, cfg.Verdict, author, cfg.Claims)
			log.Infof("adding a %s label for %s on %s", cfg.Verdict, cfg.Vulnerability, cfg.Subject)
			gates, err := loadGates([]string{cfg.Gate}, cfg.Claims, true)
			if err != nil {
				return err
			}
			g := gates[0]
			rec, err := runrecord.Load(cfg.Name, g.Name)
			if err != nil {
				return fmt.Errorf("gate %s has no scan to label from (%w); run %s first", g.Name, err, runrecord.Rerun(cfg.Name, cfg.Gate))
			}
			var sub *runrecord.Subject
			for i, s := range rec.Subjects {
				if s.Name == cfg.Subject || s.Written == cfg.Subject {
					sub = &rec.Subjects[i]
				}
			}
			if sub == nil {
				return fmt.Errorf("gate %s's last scan has no subject %q", g.Name, cfg.Subject)
			}
			set, err := claims.OpenSet(g.Claims)
			if err != nil {
				return err
			}
			now := time.Now().UTC().Format(time.RFC3339)
			l := claimsv1.Label{Package: cfg.Package, Vulnerability: cfg.Vulnerability, Verdict: claimsv1.Verdict(cfg.Verdict), Justification: cfg.Justification,
				Author: author, Notes: claimsv1.NotesOf(cfg.Note, author, now), FirstIssued: now, LastUpdated: now}
			if l.SeenIn, err = labelwrite.SeenIn(rec, runrecord.Dir(cfg.Name, g.Name), sub, l, set.Vocabulary()); err != nil {
				return err
			}
			written, err := labelwrite.Write(set, sub, l, cfg.Global)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s %s into %s\n", l.Verdict, l.Key(), written)
			return nil
		},
	}, cfg)
}

func gitUser() string {
	out, err := exec.Command("git", "config", "user.name").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
