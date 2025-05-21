package mode_add

import (
	"fmt"
	"slices"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AddRessourceBasedConstrainedDelegation adds a ressource based constrained delegation to a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to add the ressource based constrained delegation to.
//		allowedToActOnBehalfOfAnotherIdentity ([]string): The list of users or computers that the account is allowed to delegate to.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func AddRessourceBasedConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToActOnBehalfOfAnotherIdentity []string) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	searchQuery := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	searchAttributes := []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, searchAttributes)
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToActOnBehalfOfOtherIdentity: %s", err)
	}

	if len(searchResults) > 0 {
		values := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity")
		for _, value := range allowedToActOnBehalfOfAnotherIdentity {
			if !slices.Contains(values, value) {
				values = append(values, value)
			} else {
				logger.Info(fmt.Sprintf("Value %s is already present in msDS-AllowedToActOnBehalfOfOtherIdentity, not adding it again", value))
			}
		}

		err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToActOnBehalfOfOtherIdentity", values)
		if err != nil {
			return fmt.Errorf("error adding constrained delegation of %s to %s: %s", distinguishedName, allowedToActOnBehalfOfAnotherIdentity, err)
		}

		logger.Info(fmt.Sprintf("Constrained delegation added for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
