package mode_monitor

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

type DelegationState struct {
	userAccountControl                      int
	msDSAllowedToDelegateTo                 []string
	msDSAllowedToActOnBehalfOfOtherIdentity []string
}

// MonitorDelegations monitors the delegation settings of a user or computer account.
//
//	Parameters:
//		domainController (string): The domain controller to connect to.
//		ldapPort (int): The LDAP port to connect to.
//		creds (*credentials.Credentials): The credentials to use for the LDAP connection.
//		useLdaps (bool): Whether to use LDAPS for the LDAP connection.
//		useKerberos (bool): Whether to use Kerberos for the LDAP connection.
//		debug (bool): A flag indicating whether to print debug information.
//
//	Returns:
//		nil
func MonitorDelegations(domainController string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, debug bool) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(domainController, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	if debug {
		logger.Debug(fmt.Sprintf("[+] Connected to LDAP: %s", domainController))
	}

	logger.Info(fmt.Sprintf("[+] Saving current state of delegations for %s", creds.Domain))

	// Create a map to store the current state of delegations
	delegationMap := make(map[string]DelegationState)

	query := "(&"
	query += "(objectClass=computer)"
	query += "(objectClass=person)"
	query += "(objectClass=user)"
	query += ")"

	searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{})
	if err != nil {
		return fmt.Errorf("error performing LDAP search: %s", err)
	}
	for _, result := range searchResults {
		dn := result.DN
		userAccountControl, err := strconv.Atoi(result.GetAttributeValue("userAccountControl"))
		if err != nil {
			return fmt.Errorf("error converting userAccountControl to int: %s", err)
		}
		delegationState := DelegationState{
			userAccountControl:                      userAccountControl,
			msDSAllowedToDelegateTo:                 result.GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo"),
			msDSAllowedToActOnBehalfOfOtherIdentity: result.GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity"),
		}
		delegationMap[dn] = delegationState
	}

	ldapSession.Close()

	logger.Info(fmt.Sprintf("[+] Monitoring delegations for %s", creds.Domain))

	// Continuously monitor for changes
	for {
		ldapSession := ldap.Session{}
		ldapSession.InitSession(domainController, ldapPort, creds, useLdaps, useKerberos)
		success, err := ldapSession.Connect()
		if !success {
			return fmt.Errorf("error connecting to LDAP: %s", err)
		}

		// Create a new map for the current state
		newDelegationMap := make(map[string]DelegationState)
		searchResults, err := ldapSession.QueryWholeSubtree("", query, []string{})
		if err != nil {
			return fmt.Errorf("error performing LDAP search: %s", err)
		}
		for _, result := range searchResults {
			dn := result.DN
			userAccountControl, err := strconv.Atoi(result.GetAttributeValue("userAccountControl"))
			if err != nil {
				return fmt.Errorf("error converting userAccountControl to int: %s", err)
			}
			delegationState := DelegationState{
				userAccountControl:                      userAccountControl,
				msDSAllowedToDelegateTo:                 result.GetEqualFoldAttributeValues("msDS-AllowedToDelegateTo"),
				msDSAllowedToActOnBehalfOfOtherIdentity: result.GetEqualFoldAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity"),
			}
			newDelegationMap[dn] = delegationState
		}

		commonDNs := []string{}
		// Check for new objects
		for dn := range newDelegationMap {
			if _, exists := delegationMap[dn]; exists {
				commonDNs = append(commonDNs, dn)
			} else {
				logger.Info(fmt.Sprintf("[\x1b[1;92m+\x1b[0m] \x1b[1;92mObject created: %s\x1b[0m", dn))
			}
		}

		// Check for deleted objects
		for dn := range delegationMap {
			if _, exists := newDelegationMap[dn]; !exists {
				logger.Info(fmt.Sprintf("[\x1b[1;91m-\x1b[0m] \x1b[1;91mObject deleted: %s\x1b[0m", dn))
			}
		}

		for _, dn := range commonDNs {
			messages := []string{}

			newUAC := newDelegationMap[dn].userAccountControl
			oldUAC := delegationMap[dn].userAccountControl
			if newUAC != oldUAC {
				// Unconstrained delegation
				flag := int(ldap_attributes.UAF_TRUSTED_FOR_DELEGATION)
				if oldUAC&flag == 0 {
					if newUAC&flag == flag {
						messages = append(messages, fmt.Sprintf("  │ Unconstrained delegation has been set (flag UAF_TRUSTED_FOR_DELEGATION)\x1b[0m"))
					}
				}
				if oldUAC&flag == flag {
					if newUAC&flag == 0 {
						messages = append(messages, fmt.Sprintf("  │ Unconstrained delegation has been removed (flag UAF_TRUSTED_FOR_DELEGATION)\x1b[0m"))
					}
				}

				// Constrained delegation with protocol transition
				flag = int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
				if oldUAC&flag == 0 {
					if newUAC&flag == flag {
						messages = append(messages, fmt.Sprintf("  │ Constrained delegation with protocol transition has been set (flag UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)\x1b[0m"))
					}
				}
				if oldUAC&flag == flag {
					if newUAC&flag == 0 {
						messages = append(messages, fmt.Sprintf("  │ Constrained delegation with protocol transition has been removed (flag UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)\x1b[0m"))
					}
				}
			}

			constrainedDelegationMessages := []string{}
			if !slices.Equal(newDelegationMap[dn].msDSAllowedToDelegateTo, delegationMap[dn].msDSAllowedToDelegateTo) {
				// Check for added values
				for _, newValue := range newDelegationMap[dn].msDSAllowedToDelegateTo {
					if !slices.Contains(delegationMap[dn].msDSAllowedToDelegateTo, newValue) {
						constrainedDelegationMessages = append(constrainedDelegationMessages, fmt.Sprintf("  │   \x1b[1;92m+ Value added to msDS-AllowedToDelegateTo: %s\x1b[0m", newValue))
					}
				}
				// Check for removed values
				for _, oldValue := range delegationMap[dn].msDSAllowedToDelegateTo {
					if !slices.Contains(newDelegationMap[dn].msDSAllowedToDelegateTo, oldValue) {
						constrainedDelegationMessages = append(constrainedDelegationMessages, fmt.Sprintf("  │   \x1b[1;91m- Value removed from msDS-AllowedToDelegateTo: %s\x1b[0m", oldValue))
					}
				}
			}

			resourceBasedConstrainedDelegationMessages := []string{}
			if !slices.Equal(newDelegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity, delegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity) {
				// Check for added values
				for _, newValue := range newDelegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity {
					if !slices.Contains(delegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity, newValue) {
						resourceBasedConstrainedDelegationMessages = append(resourceBasedConstrainedDelegationMessages, fmt.Sprintf("  │   \x1b[1;92m+ Value added to msDS-AllowedToActOnBehalfOfOtherIdentity: %s\x1b[0m", newValue))
					}
				}
				// Check for removed values
				for _, oldValue := range delegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity {
					if !slices.Contains(newDelegationMap[dn].msDSAllowedToActOnBehalfOfOtherIdentity, oldValue) {
						resourceBasedConstrainedDelegationMessages = append(resourceBasedConstrainedDelegationMessages, fmt.Sprintf("  │   \x1b[1;91m- Value removed from msDS-AllowedToActOnBehalfOfOtherIdentity: %s\x1b[0m", oldValue))
					}
				}
			}

			if len(constrainedDelegationMessages) > 0 {
				flag := int(ldap_attributes.UAF_TRUSTED_TO_AUTH_FOR_DELEGATION)
				if newUAC&flag == flag {
					messages = append(messages, fmt.Sprintf("  │ Constrained delegation (with protocol transition) to:"))
				} else {
					messages = append(messages, fmt.Sprintf("  │ Constrained delegation to:"))
				}
				messages = append(messages, constrainedDelegationMessages...)
			}

			if len(resourceBasedConstrainedDelegationMessages) > 0 {
				messages = append(messages, fmt.Sprintf("  │ Resource-based constrained delegation:"))
				messages = append(messages, resourceBasedConstrainedDelegationMessages...)
			}

			if len(messages) > 0 {
				logger.Info(fmt.Sprintf("[\x1b[1;94m~\x1b[0m] \x1b[1;94mObject updated: %s\x1b[0m", dn))
				for _, message := range messages {
					logger.Info(message)
				}
			}
		}

		// Update the delegation map for the next iteration
		delegationMap = newDelegationMap

		ldapSession.Close()

		time.Sleep(1 * time.Second)
	}
}
