package mode_remove

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/TheManticoreProject/Delegations/core/utils"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// RemoveRessourceBasedConstrainedDelegation removes a ressource based constrained delegation from a user or computer account.
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
func RemoveRessourceBasedConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToActOnBehalfOfAnotherIdentity []string, debug bool) error {
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

		binaryAllowedToActOnBehalfOfAnotherIdentity := []string{}

		for _, value := range allowedToActOnBehalfOfAnotherIdentity {
			binaryNtSecurityDescriptor, err := utils.CreateRBCDBinaryNTSecurityDescriptor(&ldapSession, value)
			if err != nil {
				return fmt.Errorf("error creating NTSecurityDescriptor: %s", err)
			}
			binaryAllowedToActOnBehalfOfAnotherIdentity = append(binaryAllowedToActOnBehalfOfAnotherIdentity, string(binaryNtSecurityDescriptor))
		}

		newValues := []string{}
		for _, existingValue := range values {
			if !slices.Contains(binaryAllowedToActOnBehalfOfAnotherIdentity, existingValue) {
				newValues = append(newValues, existingValue)
			} else {
				logger.Info(fmt.Sprintf("Removing %s from msDS-AllowedToActOnBehalfOfOtherIdentity", existingValue))
			}
		}

		if debug {
			hexValues := []string{}
			for _, value := range values {
				hexValues = append(hexValues, hex.EncodeToString([]byte(value)))
			}
			logger.Info(fmt.Sprintf("Updated msDS-AllowedToActOnBehalfOfOtherIdentity values: [%s]", strings.Join(hexValues, ", ")))
		}

		if len(newValues) > 0 {
			err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToActOnBehalfOfOtherIdentity", newValues)
			if err != nil {
				return fmt.Errorf("error removing ressource based constrained delegation of %s from %s: %s", distinguishedName, allowedToActOnBehalfOfAnotherIdentity, err)
			}
		} else {
			logger.Info(fmt.Sprintf("No ressource based constrained delegation to remove for %s", distinguishedName))
		}

		logger.Info(fmt.Sprintf("Ressource based constrained delegation removed for %s", distinguishedName))

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
