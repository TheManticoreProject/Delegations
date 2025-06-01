package mode_add

import (
	"fmt"
	"slices"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AddConstrainedDelegationWithProtocolTransition adds a constrained delegation with protocol transition to a user or computer account.

// Parameters:
//
//	ldapHost (string): The LDAP host to connect to.
//	ldapPort (int): The LDAP port to connect to.
//	creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//	useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//	useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//	distinguishedName (string): The distinguished name of the user or computer account to add the constrained delegation with protocol transition to.
//	allowedToDelegateTo ([]string): The list of users or computers that the account is allowed to delegate to.
//	debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func AddConstrainedDelegationWithProtocolTransition(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToDelegateTo []string, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	// Check if the object exists
	exists, err := ldapSession.DistinguishedNameExists(distinguishedName)
	if err != nil {
		return fmt.Errorf("error checking if distinguished name exists: %s", err)
	}
	if !exists {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	query := "(&"
	// We are looking for either a user, computer or person
	query += "(|(objectClass=computer)(objectClass=person)(objectClass=user))"
	// Searching for the object with the given distinguished name
	query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	// Closing the first AND
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"msDS-AllowedToDelegateTo", "userAccountControl"})
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToDelegateTo: %s", err)
	}

	// Add constrained delegation with protocol transition
	if len(searchResults) > 0 {
		// Activate protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION flag)
		AddProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)

		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo")
		for _, value := range allowedToDelegateTo {
			if !slices.Contains(values, value) {
				values = append(values, value)
			} else {
				logger.Info(fmt.Sprintf("Value %s is already present in msDS-AllowedToDelegateTo, not adding it again", value))
			}
		}

		err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToDelegateTo", values)
		if err != nil {
			return fmt.Errorf("error adding constrained delegation of %s to %s: %s", distinguishedName, allowedToDelegateTo, err)
		}

		logger.Info(fmt.Sprintf("Constrained delegation added for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find a computer, person or user having a constrained delegation with protocol transition for distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
