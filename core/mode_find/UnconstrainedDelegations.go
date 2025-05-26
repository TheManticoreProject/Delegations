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
func FindUnconstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	query := "(&"
	query += "(|"
	query += "(objectClass=computer)"
	query += "(objectClass=person)"
	query += "(objectClass=user)"
	query += ")"
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{})
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
