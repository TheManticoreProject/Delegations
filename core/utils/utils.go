package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/identity"
	ace_rights "github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// DNExists checks if a distinguished name exists in LDAP
// Returns true if the distinguished name exists, false otherwise
func DNExists(ldapSession *ldap.Session, distinguishedName string) bool {
	searchResults, err := ldapSession.QueryWholeSubtree("", "(distinguishedName="+distinguishedName+")", []string{})
	if err != nil {
		return false
	}
	return len(searchResults) > 0
}

// FindTarget searches for a target based on either a distinguished name or a sAMAccountName
// Returns the target's distinguished name and an error if it exists
func FindTarget(ldapSession *ldap.Session, distinguishedName string, sAMAccountName string) (string, error) {
	if len(distinguishedName) != 0 {
		// If a distinguished name is provided, check if it exists
		if DNExists(ldapSession, distinguishedName) {
			return distinguishedName, nil
		}

	} else if len(sAMAccountName) != 0 {
		// If a sAMAccountName is provided, query LDAP for the target
		searchResults, err := ldapSession.QueryWholeSubtree("", "(sAMAccountName="+sAMAccountName+")", []string{})
		if err != nil {
			return "", fmt.Errorf("error querying LDAP: %s", err)
		}
		if len(searchResults) == 1 {
			return searchResults[0].DN, nil
		} else if len(searchResults) > 1 {
			var samAccountNames []string
			for _, entry := range searchResults {
				samAccountNames = append(samAccountNames, entry.GetAttributeValue("sAMAccountName"))
			}
			return "", fmt.Errorf("multiple targets found: %s", strings.Join(samAccountNames, ", "))
		}
	}

	return "", fmt.Errorf("no target found")
}

// LookupSID looks up a SID in LDAP and returns the corresponding object's distinguished name
// Returns the distinguished name and nil if found, empty string and error otherwise
func LookupSID(ldapSession *ldap.Session, sid string) (string, error) {
	// Construct LDAP query to find object with the given SID
	searchQuery := fmt.Sprintf("(objectSid=%s)", sid)
	searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, []string{"distinguishedName"})
	if err != nil {
		return "?", fmt.Errorf("error querying LDAP for SID %s: %s", sid, err)
	}

	if len(searchResults) == 0 {
		return "?", nil
	}

	if len(searchResults) > 1 {
		return "?", fmt.Errorf("multiple objects found with SID %s", sid)
	}

	return searchResults[0].DN, nil
}

// SIDFromValue looks up a value in LDAP and returns the corresponding SID
// Returns the SID and nil if found, empty string and error otherwise
func SIDFromValue(ldapSession *ldap.Session, value string) (*identity.SID, error) {
	if value == "" {
		return nil, fmt.Errorf("value cannot be empty")
	}
	value = strings.TrimSpace(value)

	sid := identity.SID{}

	// Check if the value is already a SID string
	if strings.HasPrefix(strings.ToUpper(value), "S-") {
		// Validate SID format with a simple regex check
		sidPattern := regexp.MustCompile(`^S-1-\d+(-\d+)+$`)
		if sidPattern.MatchString(strings.ToUpper(value)) {

			err := sid.FromString(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing SID '%s': %s", value, err)
			}

			return &sid, nil
		}
	} else {
		// Determine if the value is a sAMAccountName or a distinguished name
		valueType := "sAMAccountName"
		if strings.Contains(strings.ToUpper(value), "CN=") && strings.Contains(strings.ToUpper(value), "DC=") && strings.Contains(strings.ToUpper(value), ",") {
			valueType = "distinguishedName"
		}

		// Construct LDAP query to find object with the given value
		searchQuery := fmt.Sprintf("(%s=%s)", valueType, value)
		searchResults, err := ldapSession.QueryWholeSubtree("", searchQuery, []string{"objectSid"})
		if err != nil {
			return nil, fmt.Errorf("error querying LDAP for %s %s: %s", valueType, value, err)
		}

		if len(searchResults) == 0 {
			return nil, fmt.Errorf("no object found with %s %s", valueType, value)
		}

		if len(searchResults) > 1 {
			return nil, fmt.Errorf("multiple objects found with %s %s", valueType, value)
		}

		// Get the SID from the search result
		sidBytes := searchResults[0].GetRawAttributeValue("objectSid")
		if sidBytes == nil {
			return nil, fmt.Errorf("object found but no SID available for %s %s", valueType, value)
		}

		_, err = sid.Unmarshal(sidBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing SID '%s': %s", sidBytes, err)
		}

		return &sid, nil
	}

	return nil, fmt.Errorf("invalid SID format")
}

// CreateRBCDBinaryNTSecurityDescriptor creates a new NTSecurityDescriptor for a given SID
// Returns the NTSecurityDescriptor and nil if successful, nil and error otherwise
func CreateRBCDBinaryNTSecurityDescriptor(ldapSession *ldap.Session, value string) ([]byte, error) {
	sid, err := SIDFromValue(ldapSession, value)
	if err != nil {
		return nil, fmt.Errorf("error getting SID from value: %s", err)
	}

	ntsd := securitydescriptor.NtSecurityDescriptor{}
	ntsd.Header.Revision = 1
	ntsd.Header.Control.AddControl(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_PD)
	ntsd.Header.Control.AddControl(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_OD)

	ntsd.Owner.SID.FromString("S-1-5-32-544")
	ntsd.Group.SID.FromString("S-1-5-32-544")

	ntsd.DACL.Header.Revision.SetRevision(acl.ACL_REVISION_DS)

	a := ace.AccessControlEntry{}
	a.Index = 0
	a.Header.Type.Value = ace.ACE_TYPE_ACCESS_ALLOWED

	//  (DELETE|DS_CONTROL_ACCESS|DS_CREATE_CHILD|DS_DELETE_CHILD|DS_DELETE_TREE|DS_LIST_CONTENTS|DS_LIST_OBJECT|DS_READ_PROPERTY|DS_WRITE_PROPERTY|DS_WRITE_PROPERTY_EXTENDED|READ_CONTROL|WRITE_DAC|WRITE_OWNER)
	a.Mask.SetRights([]uint32{
		ace_rights.RIGHT_DELETE,
		ace_rights.RIGHT_DS_CONTROL_ACCESS,
		ace_rights.RIGHT_DS_CREATE_CHILD,
		ace_rights.RIGHT_DS_DELETE_CHILD,
		ace_rights.RIGHT_DS_DELETE_TREE,
		ace_rights.RIGHT_DS_LIST_CONTENTS,
		ace_rights.RIGHT_DS_LIST_OBJECT,
		ace_rights.RIGHT_DS_READ_PROPERTY,
		ace_rights.RIGHT_DS_WRITE_PROPERTY,
		ace_rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED,
		ace_rights.RIGHT_READ_CONTROL,
		ace_rights.RIGHT_WRITE_DAC,
		ace_rights.RIGHT_WRITE_OWNER,
	})
	a.SID.SID = *sid

	ntsd.DACL.AddEntry(a)

	binaryNTSecurityDescriptor, err := ntsd.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshalling NTSecurityDescriptor: %s", err)
	}

	return binaryNTSecurityDescriptor, nil
}
