package utils

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/ldap"
)

// DNExists checks if a distinguished name exists in LDAP
// Returns true if the distinguished name exists, false otherwise
func DNExists(ldapSession *ldap.Session, distinguishedName string) bool {
	searchResults, err := ldapSession.QueryWholeSubtree("", "(distinguishedName="+distinguishedName+")", []string{})
	if err != nil {
		return false
	}
	return len(searchResults) > 0
}

// FindTarget searches for a target based on either a distinguished name or a sAMAccountName
// Returns the target's distinguished name and an error if it exists
func FindTarget(ldapSession *ldap.Session, distinguishedName string, sAMAccountName string) (string, error) {
	if len(distinguishedName) != 0 {
		// If a distinguished name is provided, check if it exists
		if DNExists(ldapSession, distinguishedName) {
			return distinguishedName, nil
		}

	} else if len(sAMAccountName) != 0 {
		// If a sAMAccountName is provided, query LDAP for the target
		searchResults, err := ldapSession.QueryWholeSubtree("", "(sAMAccountName="+sAMAccountName+")", []string{})
		if err != nil {
			return "", fmt.Errorf("error querying LDAP: %s", err)
		}
		if len(searchResults) == 1 {
			return searchResults[0].DN, nil
		} else if len(searchResults) > 1 {
			var samAccountNames []string
			for _, entry := range searchResults {
				samAccountNames = append(samAccountNames, entry.GetAttributeValue("sAMAccountName"))
			}
			return "", fmt.Errorf("multiple targets found: %s\n", strings.Join(samAccountNames, ", "))
		}
	}

	return "", fmt.Errorf("no target found")
}
