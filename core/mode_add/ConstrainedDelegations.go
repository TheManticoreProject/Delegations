package mode_add

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func AddConstrainedDelegation(ldapHost string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, distinguishedName string, AllowedToDelegateTo []string) error {
	ldapSession := ldap.Session{}
	ldapSession.InitSession(ldapHost, ldapPort, creds, useLdaps, useKerberos)
	success, err := ldapSession.Connect()
	if !success {
		return fmt.Errorf("error connecting to LDAP: %s", err)
	}

	modifyRequest := ldap.NewModifyRequest(distinguishedName)
	modifyRequest.Replace("msDS-AllowedToDelegateTo", AllowedToDelegateTo)
	err = ldapSession.Modify(modifyRequest)
	if err != nil {
		return fmt.Errorf("error adding constrained delegation: %s", err)
	}

	logger.Info(fmt.Sprintf("Constrained delegation added for %s\n", distinguishedName))

	ldapSession.Close()

	return nil
}
