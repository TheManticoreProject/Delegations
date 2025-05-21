package mode_remove

import (
	"fmt"
	"slices"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// RemoveConstrainedDelegation removes a constrained delegation from a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to remove the constrained delegation from.
//		allowedToDelegateTo ([]string): The list of users or computers that the account is allowed to delegate to.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func RemoveConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToDelegateTo []string) error {
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

		newValues := []string{}
		for _, existingValue := range values {
			if !slices.Contains(allowedToDelegateTo, existingValue) {
				newValues = append(newValues, existingValue)
			} else {
				logger.Info(fmt.Sprintf("Removing %s from msDS-AllowedToDelegateTo", existingValue))
			}
		}

		err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToDelegateTo", newValues)
		if err != nil {
			return fmt.Errorf("error removing constrained delegation of %s from %s: %s", distinguishedName, allowedToDelegateTo, err)
		}

		logger.Info(fmt.Sprintf("Constrained delegation removed for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
