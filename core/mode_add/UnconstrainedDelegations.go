package mode_add

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AddUnconstrainedDelegation adds an unconstrained delegation to a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to add the unconstrained delegation to.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func AddUnconstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}
	searchQuery := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	searchAttributes := []string{"userAccountControl"}
	searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, searchAttributes)
	if err != nil {
		return fmt.Errorf("error querying userAccountControl: %s", err)
	}

	if len(searchResults) > 0 {
		// Get current userAccountControl value
		uacValue := 0
		uacStr := searchResults[0].GetAttributeValue("userAccountControl")
		uacValue, err = strconv.Atoi(uacStr)
		if err != nil {
			return fmt.Errorf("error converting userAccountControl to integer: %s", err)
		}

		// Add TRUSTED_FOR_DELEGATION flag (0x80000)
		uacValue |= int(ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)

		// Update the userAccountControl attribute
		err = ldapSession.OverwriteAttributeValues(distinguishedName, "userAccountControl", []string{fmt.Sprintf("%d", uacValue)})
		if err != nil {
			return fmt.Errorf("error setting unconstrained delegation for %s: %s", distinguishedName, err)
		}

		logger.Info(fmt.Sprintf("Unconstrained delegation added for %s", distinguishedName))
	} else {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
