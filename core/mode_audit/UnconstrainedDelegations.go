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
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func AuditUnconstrainedDelegations(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, debug bool, ignoreLegitimate bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	query := "(&"
	// We are looking for either a user, computer or person
	query += "(|(objectClass=computer)(objectClass=person)(objectClass=user))"
	if len(distinguishedName) > 0 {
		// Searching for the object with the given distinguished name
		query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	}
	// With the userAccountControl attribute set to the flag UAF_TRUSTED_FOR_DELEGATION (unconstrained delegation)
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
	// Closing the first AND
	query += ")"
	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{"userAccountControl"})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Unconstrained Delegations (\x1b[93m%d\x1b[0m):", len(searchResults)))
		for k, entry := range searchResults {
			userAccountControl, err := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
			if err != nil {
				logger.Warn(fmt.Sprintf("Error getting userAccountControl: %s", err))
				continue
			}

			auditString := ""
			if userAccountControl&int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) == int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) {
				if ignoreLegitimate {
					auditString = ""
				} else {
					auditString = "(\x1b[92mLegitimate\x1b[0m: DC)"
				}
			} else if userAccountControl&int(ldap_attributes.UAF_PARTIAL_SECRETS_ACCOUNT) == int(ldap_attributes.UAF_SERVER_TRUST_ACCOUNT) {
				auditString = "(\x1b[91mSuspicious\x1b[0m: RODCs do not have unconstrained delegation by default)"
			} else {
				auditString = "(\x1b[91mSuspicious\x1b[0m)"
			}

			// Print the audit string
			if len(auditString) > 0 {
				if k < len(searchResults)-1 {
					logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
				} else {
					logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
				}
			}
		}
		logger.Print("")
	} else {
		logger.Print("[>] Unconstrained Delegations (0)")
	}

	// Query for DCs without unconstrained delegation
	query = "(&"
	// Looking for domain controllers
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_SERVER_TRUST_ACCOUNT)
	// Without unconstrained delegation flag
	query += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
	// That are not RODCs
	query += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_PARTIAL_SECRETS_ACCOUNT)
	// Searching for the object with the given distinguished name
	if len(distinguishedName) > 0 {
		query += fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	}
	query += ")"
	searchResults, err = ldapSession.QueryWholeSubtree("", query, []string{"userAccountControl"})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}

	if len(searchResults) != 0 {
		logger.Print(fmt.Sprintf("[>] Domain Controllers without Unconstrained Delegation (\x1b[93m%d\x1b[0m):", len(searchResults)))
		for k, entry := range searchResults {
			auditString := "(\x1b[91mSuspicious\x1b[0m: DCs should have unconstrained delegation)"

			if k < len(searchResults)-1 {
				logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
			} else {
				logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m %s", entry.DN, auditString))
			}
		}
		logger.Print("")
	}

	ldapSession.Close()

	return nil
}
