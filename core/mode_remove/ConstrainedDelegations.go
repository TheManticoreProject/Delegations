package mode_remove

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
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
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func RemoveConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToDelegateTo []string, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	query := "(&"
	query += "(|"
	query += "(objectClass=computer)"
	query += "(objectClass=person)"
	query += "(objectClass=user)"
	query += ")"
	query += "(&"
	query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	query += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
	query += ")"
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"msDS-AllowedToDelegateTo"})
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToDelegateTo: %s", err)
	}

	if len(searchResults) > 0 {
		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo")

		if len(values) == 0 {
			logger.Info(fmt.Sprintf("No msDS-AllowedToDelegateTo exists for %s", distinguishedName))
			return nil
		}

		newValues := []string{}
		for _, existingValue := range values {
			shouldKeep := true
			for _, valueToRemove := range allowedToDelegateTo {
				if existingValue == valueToRemove {
					logger.Info(fmt.Sprintf("Removing %s from msDS-AllowedToDelegateTo", existingValue))
					shouldKeep = false
					break
				}
			}
			if shouldKeep {
				newValues = append(newValues, existingValue)
			}
		}

		if debug {
			logger.Debug(fmt.Sprintf("New msDS-AllowedToDelegateTo values: %v", newValues))
		}

		if len(newValues) == 0 {
			logger.Info(fmt.Sprintf("No msDS-AllowedToDelegateTo values left for %s", distinguishedName))

			err = ldapSession.FlushAttribute(distinguishedName, "msDS-AllowedToDelegateTo")
			if err != nil {
				return fmt.Errorf("error flushing msDS-AllowedToDelegateTo: %s", err)
			}
		} else {
			err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToDelegateTo", newValues)
			if err != nil {
				return fmt.Errorf("error removing constrained delegation of %s from %s: %s", distinguishedName, allowedToDelegateTo, err)
			}
		}

		logger.Info(fmt.Sprintf("Constrained delegation removed for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
