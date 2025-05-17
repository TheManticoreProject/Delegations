package mode_audit

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AuditRessourceBasedConstrainedDelegations retrieves resource-based constrained delegations for a given domain controller.
//
// Parameters:
//
//	domainController (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The port number to connect to on the LDAP server. Must be in the range 1-65535.
//	creds (*credentials.Credentials): The credentials for authentication.
//	useLdaps (bool): A flag indicating whether to use LDAPS (LDAP over SSL).
//	useKerberos (bool): A flag indicating whether to use Kerberos for authentication.
//
// Example:
//
//	creds, err := credentials.NewCredentials("EXAMPLE", "user", "password", "")
//	if err != nil {
//		fmt.Printf("[error] Error creating credentials: %s\n", err)
//		return
//	}
//	FindRessourceBasedConstrainedDelegations("ldap.example.com", 389, creds, false, true)
//
// Note:
//
//	This function initializes an LDAP session, connects to the LDAP server, retrieves the domain information,
//	and then closes the session. If any step fails, it prints an error message and returns.
func AuditRessourceBasedConstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool) {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		fmt.Printf("[error] Error connecting to LDAP: %s\n", err)
		return
	}

	query := "(&"
	query += "(|"
	query += "(objectClass=computer)"
	query += "(objectClass=person)"
	query += "(objectClass=user)"
	query += ")"
	query += "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{})
	if err != nil {
		logger.Warn(fmt.Sprintf("Error performing LDAP search: %s\n", err))
		return
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Resource-Based Constrained Delegations (\x1b[1;93m%d\x1b[0m):", len(searchResults)))
		for entryIndex, entry := range searchResults {
			if entryIndex < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", entry.DN))
			} else {
				logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", entry.DN))
			}

			values := entry.GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity")
			if entryIndex < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  │   └── msDS-AllowedToActOnBehalfOfOtherIdentity (%d):", len(values)))
			} else {
				logger.Print(fmt.Sprintf("      └── msDS-AllowedToActOnBehalfOfOtherIdentity (%d):", len(values)))
			}
			for valueIndex, value := range values {
				if entryIndex < len(searchResults)-1 {
					if valueIndex < len(values)-1 {
						logger.Print(fmt.Sprintf("  │       ├── \x1b[94m%s\x1b[0m", value))
					} else {
						logger.Print(fmt.Sprintf("  │       └── \x1b[94m%s\x1b[0m", value))
					}
				} else {
					if valueIndex < len(values)-1 {
						logger.Print(fmt.Sprintf("          ├── \x1b[94m%s\x1b[0m", value))
					} else {
						logger.Print(fmt.Sprintf("          └── \x1b[94m%s\x1b[0m", value))
					}
				}
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Resource-Based Constrained Delegations (0)")
	}

	ldapSession.Close()
}
