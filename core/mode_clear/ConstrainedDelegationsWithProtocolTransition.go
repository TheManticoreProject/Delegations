package mode_clear

import (
	"fmt"

	"github.com/TheManticoreProject/Delegations/core/mode_remove"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// ClearConstrainedDelegationWithProtocolTransition clears a constrained delegation with protocol transition from a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to clear the constrained delegation from.
//		allowedToDelegateTo ([]string): The list of users or computers that the account is allowed to delegate to.
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func ClearConstrainedDelegationWithProtocolTransition(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool) error {
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
	query += "(&"
	// Searching for the object with the given distinguished name
	query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	// With the userAccountControl attribute with the flag UAF_TRUSTED_TO_AUTH_FOR_DELEGATION set (protocol transition enabled)
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
	query += ")"
	// Closing the first AND
	query += ")"

	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"msDS-AllowedToDelegateTo"})
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToDelegateTo: %s", err)
	}

	// Clear constrained delegation with protocol transition
	if len(searchResults) > 0 {
		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo")

		if len(values) == 0 {
			logger.Info(fmt.Sprintf("Attribute msDS-AllowedToDelegateTo is empty for %s", distinguishedName))
			return nil
		} else {
			err = ldapSession.FlushAttributeValues(distinguishedName, "msDS-AllowedToDelegateTo")
			if err != nil {
				return fmt.Errorf("error clearing msDS-AllowedToDelegateTo: %s", err)
			}

			mode_remove.RemoveProtocolTransition(ldapHost, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		}

		logger.Info(fmt.Sprintf("Constrained delegation with protocol transition cleared for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find a computer, person or user having a constrained delegation with protocol transition for distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
