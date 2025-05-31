package mode_clear

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// ClearRessourceBasedConstrainedDelegation removes a ressource based constrained delegation from a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to remove the ressource based constrained delegation from.
//		allowedToActOnBehalfOfAnotherIdentity ([]string): The list of users or computers that the account is allowed to delegate to.
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func ClearRessourceBasedConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool) error {
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

	searchQuery := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToActOnBehalfOfOtherIdentity: %s", err)
	}

	// Clear ressource based constrained delegation
	if len(searchResults) > 0 {
		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity")

		if len(values) == 0 {
			logger.Info(fmt.Sprintf("Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty for %s", distinguishedName))
			return nil
		} else {
			err = ldapSession.FlushAttributeValues(distinguishedName, "msDS-AllowedToActOnBehalfOfOtherIdentity")
			if err != nil {
				return fmt.Errorf("error clearing msDS-AllowedToActOnBehalfOfOtherIdentity: %s", err)
			}
		}

		logger.Info(fmt.Sprintf("Ressource based constrained delegation cleared for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find a computer, person or user having a ressource based constrained delegation for distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
