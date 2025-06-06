package mode_audit

import (
	"fmt"

	"github.com/TheManticoreProject/Delegations/core/utils"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AuditConstrainedDelegations retrieves constrained delegations for a given domain controller.
//
// Parameters:
//
//	domainController (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The port number to connect to on the LDAP server. Must be in the range 1-65535.
//	creds (*credentials.Credentials): The credentials for authentication.
//	useLdaps (bool): A flag indicating whether to use LDAPS (LDAP over SSL).
//	useKerberos (bool): A flag indicating whether to use Kerberos for authentication.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func AuditConstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	query := "(&"
	// We are looking for either a user, computer or person
	query += "(|(objectClass=computer)(objectClass=person)(objectClass=user))"
	query += "(&"
	if len(distinguishedName) > 0 {
		// Searching for the object with the given distinguished name
		query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	}
	// Searching for non empty msDS-AllowedToDelegateTo attribute
	query += "(msDS-AllowedToDelegateTo=*)"
	// With the userAccountControl attribute cleared of the flag UAF_TRUSTED_TO_AUTH_FOR_DELEGATION set (protocol transition disabled)
	query += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
	// Closing the second AND
	query += ")"
	// Closing the first AND
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"msDS-AllowedToDelegateTo"})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Constrained Delegations (\x1b[93m%d\x1b[0m):", len(searchResults)))
		for entryIndex, entry := range searchResults {
			if entryIndex < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", entry.DN))
			} else {
				logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", entry.DN))
			}

			values := entry.GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo")
			if entryIndex < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  │   └── msDS-AllowedToDelegateTo (%d):", len(values)))
			} else {
				logger.Print(fmt.Sprintf("      └── msDS-AllowedToDelegateTo (%d):", len(values)))
			}
			for valueIndex, value := range values {
				var separator string
				if valueIndex < len(values)-1 {
					separator = "├──"
				} else {
					separator = "└──"
				}

				// Format the string depending on if the SID lookup failed or not
				spnExists, _ := utils.SPNExists(&ldapSession, value)
				var formattedString string
				if spnExists {
					formattedString = fmt.Sprintf("%s \x1b[92m%s\x1b[0m", separator, value)
				} else {
					formattedString = fmt.Sprintf("%s \x1b[91m%s\x1b[0m (\x1b[91mUnknown SPN\x1b[0m)", separator, value)
				}

				if entryIndex < len(searchResults)-1 {
					logger.Print(fmt.Sprintf("  │       %s", formattedString))
				} else {
					logger.Print(fmt.Sprintf("          %s", formattedString))
				}
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Constrained Delegations (0)")
	}

	ldapSession.Close()

	return nil
}
