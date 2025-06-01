package mode_add

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AddProtocolTransition adds a protocol transition to a user or computer account.
//
//	Parameters:
//		ldapHost (string): The LDAP host to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		distinguishedName (string): The distinguished name of the user or computer account to add the protocol transition to.
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		error: An error if the operation fails, nil otherwise.
func AddProtocolTransition(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool) error {
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

	searchResults, err := ldapSession.QueryWholeSubtree("", fmt.Sprintf("(distinguishedName=%s)", distinguishedName), []string{"userAccountControl"})
	if err != nil {
		return fmt.Errorf("error querying userAccountControl: %s", err)
	}

	// Add protocol transition
	if len(searchResults) > 0 {
		// Check if protocol transition is activated (TRUSTED_TO_AUTH_FOR_DELEGATION flag)
		uacValue := searchResults[0].GetAttributeValue("userAccountControl")
		uacValueInt, err := strconv.Atoi(uacValue)
		if err != nil {
			return fmt.Errorf("error converting userAccountControl to integer: %s", err)
		}
		if uacValueInt&int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION) == 0 {
			// Protocol transition is not enabled, we need to enable it
			newUacValue := uacValueInt | int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
			err = ldapSession.OverwriteAttributeValues(distinguishedName, "userAccountControl", []string{fmt.Sprintf("%d", newUacValue)})
			if err != nil {
				return fmt.Errorf("error enabling protocol transition for %s: %s", distinguishedName, err)
			}
			logger.Info(fmt.Sprintf("Protocol transition enabled for %s", distinguishedName))
		} else {
			logger.Info(fmt.Sprintf("Protocol transition already enabled for %s", distinguishedName))
		}
	} else {
		return fmt.Errorf("could not find a computer, person or user having a constrained delegation without protocol transition for distinguished name: %s", distinguishedName)
	}

	ldapSession.Close()

	return nil
}
