package mode_audit

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// AuditUnconstrainedDelegations retrieves unconstrained delegations for a given domain controller.
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
func AuditUnconstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool) {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		logger.Warn(fmt.Sprintf("Error performing LDAP search: %s\n", err))
		return
	}

	query := "(&"
	query += "(|"
	query += "(objectClass=computer)"
	query += "(objectClass=person)"
	query += "(objectClass=user)"
	query += ")"
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"sAMAccountType", "userAccountControl"})
	if err != nil {
		fmt.Printf("[error] Error performing LDAP search: %s\n", err)
		return
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Unconstrained Delegations (\x1b[1;93m%d\x1b[0m):", len(searchResults)))
		for k, entry := range searchResults {
			userAccountControl, err := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
			if err != nil {
				logger.Warn(fmt.Sprintf("Error getting sAMAccountType: %s", err))
				continue
			}

			auditString := ""
			if userAccountControl&int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) == int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) {
				auditString = "(\x1b[1;92mLegitimate\x1b[0m: DC)"
			} else if userAccountControl&int(ldap_attributes.UAF_PARTIAL_SECRETS_ACCOUNT) == int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) {
				auditString = "(\x1b[1;91mSuspicious\x1b[0m: RODCs do not have unconstrained delegation by default)"
			} else {
				auditString = "(\x1b[1;91mSuspicious\x1b[0m)"
			}

			// Print the audit string
			if k < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
			} else {
				logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Unconstrained Delegations (0)")
	}

	ldapSession.Close()
}
