package common

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Filter struct {
	include *FilterRuleSet
	exclude *FilterRuleSet
}

type FilterRuleSet []regexp.Regexp

// FilterEmpty returns a Filter that always passes.
func FilterEmpty() *Filter {
	filter, err := FilterFromFiles("", "", true)
	if err != nil {
		log.WithError(err).Fatalf("could not create empty filter")
	}
	return filter
}

// FilterNoRules returns a Filter that never passes.
func FilterNoRules() *Filter {
	return &Filter{
		include: &FilterRuleSet{},
		exclude: &FilterRuleSet{},
	}
}

// FilterFromFiles creates a Filter using the rules in the provided include and exclude files.
func FilterFromFiles(includeFilterPath string, excludeFilterPath string, allowRegexp bool) (*Filter, error) {
	includeRules, err := FilterRulesFromFile(includeFilterPath, allowRegexp)
	if err != nil {
		return nil, fmt.Errorf("could not create include rules: %s", err)
	}
	excludeRules, err := FilterRulesFromFile(excludeFilterPath, allowRegexp)
	if err != nil {
		return nil, fmt.Errorf("could not create exclude rules: %s", err)
	}

	// If no includeFilterPath is provided, every pattern should pass the include rules.
	if includeFilterPath == "" {
		includeRules = &FilterRuleSet{*regexp.MustCompile("")}
	}

	filter := &Filter{
		include: includeRules,
		exclude: excludeRules,
	}

	return filter, nil
}

// FilterRulesFromFile loads the list of regular expression filter rules in `source` and creates a FilterRuleSet.
func FilterRulesFromFile(source string, allowRegexp bool) (*FilterRuleSet, error) {
	rules := FilterRuleSet{}
	if source == "" {
		return &rules, nil
	}

	commentPattern := regexp.MustCompile(`^\s*#`)

	file, err := os.Open(source)
	if err != nil {
		log.WithError(err).Fatalf("unable to open filter file: %s", source)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.WithError(err).Fatalf("unable to close filter file: %s", source)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || commentPattern.MatchString(line) {
			continue
		}
		if !allowRegexp {
			line = regexp.QuoteMeta(line)
		}
		pattern, err := regexp.Compile(line)
		if err != nil {
			return nil, fmt.Errorf("can not compile regular expression: %s", line)
		}
		log.Tracef("Filter rule: %s", *pattern)
		rules = append(rules, *pattern)
	}
	return &rules, nil
}

// Pass returns true if the include FilterRuleSet matches the pattern and the exclude FilterRuleSet does not match.
func (filter *Filter) Pass(object string) bool {
	excluded := filter.exclude.Matches(object)
	included := filter.include.Matches(object)
	return !excluded && included
}

// Matches will return true if any of the regular expressions in the FilterRuleSet match the pattern.
func (rules *FilterRuleSet) Matches(object string) bool {
	if rules == nil {
		return false
	}
	for _, rule := range *rules {
		if rule.MatchString(object) {
			return true
		}
	}
	return false
}
