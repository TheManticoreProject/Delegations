package mode_remove

import (
	"bytes"
	"encoding/hex"
	"fmt"

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

	// Check if the object exists
	exists, err := ldapSession.DistinguishedNameExists(distinguishedName)
	if err != nil {
		return fmt.Errorf("error checking if distinguished name exists: %s", err)
	}
	if !exists {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	searchResults, err := ldapSession.QueryWholeSubtree("", fmt.Sprintf("(distinguishedName=%s)", distinguishedName), []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if err != nil {
		return fmt.Errorf("error querying msDS-AllowedToActOnBehalfOfOtherIdentity: %s", err)
	}

	// Remove ressource based constrained delegation
	if len(searchResults) > 0 {
		existingValues := searchResults[0].GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity")
		if len(existingValues) > 1 {
			return fmt.Errorf("multiple msDS-AllowedToActOnBehalfOfOtherIdentity values found for %s, this should not be possible", distinguishedName)
		}

		oldRBCDNtSecurityDescriptor := []byte{}
		if len(existingValues) != 0 {
			oldRBCDNtSecurityDescriptor = []byte(existingValues[0])
		}
		binaryNtSecurityDescriptor, err := utils.UpdateNTSecurityDescriptorDACL(&ldapSession, oldRBCDNtSecurityDescriptor, []string{}, allowedToActOnBehalfOfAnotherIdentity, debug)
		if err != nil {
			return fmt.Errorf("error updating NTSecurityDescriptor: %s", err)
		}

		if debug {
			logger.Info(fmt.Sprintf("Updated msDS-AllowedToActOnBehalfOfOtherIdentity value: %s", hex.EncodeToString(binaryNtSecurityDescriptor)))
		}

		if !bytes.Equal(binaryNtSecurityDescriptor, oldRBCDNtSecurityDescriptor) {
			err = ldapSession.OverwriteAttributeValues(distinguishedName, "msDS-AllowedToActOnBehalfOfOtherIdentity", existingValues)
			if err != nil {
				return fmt.Errorf("error removing ressource-based constrained delegation of %s to %s: %s", distinguishedName, allowedToActOnBehalfOfAnotherIdentity, err)
			}
			logger.Info(fmt.Sprintf("Ressource-based constrained delegation removed for %s", distinguishedName))
		} else {
			logger.Info(fmt.Sprintf("No changes made to msDS-AllowedToActOnBehalfOfOtherIdentity for %s", distinguishedName))
		}

	} else {
		return fmt.Errorf("could not find a computer, person or user having a ressource based constrained delegation for distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
