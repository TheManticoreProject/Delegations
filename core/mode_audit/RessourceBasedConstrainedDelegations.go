package mode_audit

import (
	"fmt"

	"github.com/TheManticoreProject/Delegations/core/utils"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
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
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func AuditRessourceBasedConstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, debug bool) error {
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
	query += "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Resource-Based Constrained Delegations (\x1b[93m%d\x1b[0m):", len(searchResults)))
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
				var separator string
				if valueIndex < len(values)-1 {
					separator = "├──"
				} else {
					separator = "└──"
				}

				ntSecurityDescriptor := securitydescriptor.NtSecurityDescriptor{}
				_, err := ntSecurityDescriptor.Unmarshal([]byte(value))
				if err != nil {
					return fmt.Errorf("error creating security descriptor: %s", err)
				}
				for _, entry := range ntSecurityDescriptor.DACL.Entries {
					sidString := entry.Identity.SID.ToString()
					distingushedName, err := utils.LookupSID(&ldapSession, sidString)

					// Format the string depending on if the SID lookup failed or not
					var formattedString string
					if err != nil {
						formattedString = fmt.Sprintf("%s \x1b[91m%s\x1b[0m (\x1b[91mUnknown SID\x1b[0m)", separator, sidString)
					} else {
						formattedString = fmt.Sprintf("%s \x1b[92m%s\x1b[0m", separator, distingushedName)
					}

					// Print the formatted string
					if entryIndex < len(searchResults)-1 {
						logger.Print("  │       " + formattedString)
					} else {
						logger.Print("          " + formattedString)
					}
				}
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Resource-Based Constrained Delegations (0)")
	}

	ldapSession.Close()

	return nil
}
