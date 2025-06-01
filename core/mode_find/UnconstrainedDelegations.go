package mode_find

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// FindUnconstrainedDelegations retrieves unconstrained delegations for a given domain controller.
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
func FindUnconstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	query := "(&"
	// We are looking for either a user, computer or person
	query += "(|(objectClass=computer)(objectClass=person)(objectClass=user))"
	if len(distinguishedName) > 0 {
		// Searching for the object with the given distinguished name
		query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	}
	// With the userAccountControl attribute with the flag UAF_TRUSTED_FOR_DELEGATION set (unconstrained delegation enabled)
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
	// Closing the first AND
	query += ")"
	// Querying the userAccountControl attribute
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"userAccountControl"})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Unconstrained Delegations (\x1b[93m%d\x1b[0m):", len(searchResults)))
		for k, entry := range searchResults {
			if k < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", entry.DN))
			} else {
				logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", entry.DN))
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Unconstrained Delegations (0)")
	}

	ldapSession.Close()

	return nil
}
