package mode_remove

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func RemoveProtocolTransition(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string) error {
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

	if len(searchResults) == 0 {
		return fmt.Errorf("could not find an object with distinguished name: %s", distinguishedName)
	}

	// Check if protocol transition is activated (TRUSTED_TO_AUTH_FOR_DELEGATION flag)
	uacValue := searchResults[0].GetAttributeValue("userAccountControl")
	uacValueInt, err := strconv.Atoi(uacValue)
	if err != nil {
		return fmt.Errorf("error converting userAccountControl to integer: %s", err)
	}
	if uacValueInt&int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0 {
		// Protocol transition is enabled, we need to disable it
		newUacValue := uacValueInt &^ int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
		err = ldapSession.OverwriteAttributeValues(distinguishedName, "userAccountControl", []string{fmt.Sprintf("%d", newUacValue)})
		if err != nil {
			return fmt.Errorf("error disabling protocol transition for %s: %s", distinguishedName, err)
		}
		logger.Info(fmt.Sprintf("Protocol transition disabled for %s", distinguishedName))
	} else {
		logger.Info(fmt.Sprintf("Protocol transition already disabled for %s", distinguishedName))
	}

	ldapSession.Close()

	return nil
}
