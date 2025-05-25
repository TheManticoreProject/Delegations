package mode_add

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
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func AddRessourceBasedConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, allowedToActOnBehalfOfAnotherIdentity []string, debug bool) error {
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
			binaryNtSecurityDescriptor, err := utils.CreateRBCDBinaryNTSecurityDescriptor(&ldapSession, value)
			if err != nil {
				return fmt.Errorf("error creating NTSecurityDescriptor: %s", err)
			}
			if !slices.Contains(values, string(binaryNtSecurityDescriptor)) {
				values = append(values, string(binaryNtSecurityDescriptor))
			} else {
				logger.Info(fmt.Sprintf("Value %s is already present in msDS-AllowedToActOnBehalfOfOtherIdentity, not adding it again", value))
			}
		}

		if debug {
			hexValues := []string{}
			for _, value := range values {
				hexValues = append(hexValues, hex.EncodeToString([]byte(value)))
			}
			logger.Info(fmt.Sprintf("Updated msDS-AllowedToActOnBehalfOfOtherIdentity values: [%s]", strings.Join(hexValues, ", ")))
		}

		if len(values) > 0 {
			err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToActOnBehalfOfOtherIdentity", values)
			if err != nil {
				return fmt.Errorf("error adding ressource-based constrained delegation of %s to %s: %s", distinguishedName, allowedToActOnBehalfOfAnotherIdentity, err)
			}
			logger.Info(fmt.Sprintf("Ressource-based constrained delegation added for %s", distinguishedName))
		} else {
			logger.Info(fmt.Sprintf("No ressource-based constrained delegation added for %s", distinguishedName))
		}

	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
