package mode_add

import (
	"fmt"
	"slices"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func AddConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToDelegateTo []string) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	searchQuery := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	searchAttributes := []string{"msDS-AllowedToDelegateTo"}
	searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, searchAttributes)
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToDelegateTo: %s", err)
	}

	if len(searchResults) > 0 {
		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo")
		for _, value := range allowedToDelegateTo {
			if !slices.Contains(values, value) {
				values = append(values, value)
			}
		}

		modifyRequest := ldap.NewModifyRequest(distinguishedName)
		modifyRequest.Overwrite("msDS-AllowedToDelegateTo", values)
		err = ldapSession.Modify(modifyRequest)
		if err != nil {
			return fmt.Errorf("error adding constrained delegation of %s to %s: %s", distinguishedName, allowedToDelegateTo, err)
		}

		logger.Info(fmt.Sprintf("Constrained delegation added for %s\n", distinguishedName))

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
