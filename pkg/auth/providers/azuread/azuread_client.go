package azuread

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/rancher/norman/httperror"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/apis/management.cattle.io/v3public"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AzureADClient struct {
	httpClient *http.Client
}

func (ac *AzureADClient) getAccessToken(adCredential *v3public.BasicLogin, config *v3.AzureADConfig) (string, error) {
	if isConfigured(config) == false {
		logrus.Errorf("Azure Client and Tenant Id not configured")
		return "", httperror.NewAPIError(httperror.ServerError, "Azure Client and Tenant Id not configured")
	}

	username := adCredential.Username
	password := adCredential.Password
	if username == "" || password == "" {
		return "", httperror.NewAPIError(httperror.MissingRequired, "username or password not provided")
	}
	domain := config.Domain
	endsWith := strings.HasSuffix("username", "@"+domain)
	if domain != "" && endsWith == false {
		username = username + "@" + domain
	}

	body := bytes.Buffer{}
	body.WriteString("scope=openid&grant_type=password&resource=https%3A%2F%2Fgraph.windows.net")
	body.WriteString("&client_id=")
	body.WriteString(config.ClientID)
	body.WriteString("&username=")
	body.WriteString(username)
	body.WriteString("&password=")
	body.WriteString(password)

	url, err := ac.getURL("TOKEN", config, "")
	//if err != nil {
	//	logrus.Errorf("AzureAD GET url received error from azuread, err: %v")
	//	return "", err
	//}

	resp, err := ac.postToAzureAD(url, body.String())
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azuread, err: %v", url, err)
		return "", err
	}
	defer resp.Body.Close()

	// Decode the response
	var respMap map[string]interface{}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error reading response body, err: %v", err)
		return "", err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", err
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		logrus.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
		return "", fmt.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
	}

	acessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}
	return acessToken, nil
}

func (ac *AzureADClient) postToAzureAD(url string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		logrus.Error(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("Received error from azuread: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (ac *AzureADClient) getUser(azureAccessToken string, config *v3.AzureADConfig) (AzureADAccount, error) {
	url, err := ac.getURL("USER", config, "")

	resp, err := ac.getFromAzureAD(azureAccessToken, url)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: GET url %v received error from github, err: %v", url, err)
		return AzureADAccount{}, err
	}
	defer resp.Body.Close()
	var azureADAcct AzureADAccount

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error reading response, err: %v", err)
		return AzureADAccount{}, err
	}

	if err := json.Unmarshal(b, &azureADAcct); err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error unmarshalling response, err: %v", err)
		return AzureADAccount{}, err
	}

	return azureADAcct, nil
}

func (ac *AzureADClient) searchPrincipals(name, principalType string, config *v3.AzureADConfig) ([]v3.Principal, error) {
	var principals []v3.Principal

	if principalType == "" || principalType == "user" {
		princs, err := ac.searchUser(name, config)
		if err != nil {
			return nil, err
		}
		principals = append(principals, princs...)
	}

	//if principalType == "" || principalType == "group" {
	//	princs, err := ac.searchGroup(name, config)
	//	if err != nil {
	//		return nil, err
	//	}
	//	principals = append(principals, princs...)
	//}

	return principals, nil
}

func (ac *AzureADClient) searchUser(name string, config *v3.AzureADConfig) ([]v3.Principal, error) {

	return ac.getAzureUserByName(name)
}

func (ac *AzureADClient) getAzureUserByName(name string) ([]v3.Principal, error) {
	var result []v3.Principal
	principal := &v3.Principal{
		//ObjectMeta:  metav1.ObjectMeta{Name: scope + "://" + externalID},
		//DisplayName: externalID,
		//PrincipalType: kind,
		Provider: Name,
	}
	result = append(result, *principal)
	return result, nil
}

func (ac *AzureADClient) getPrincipal(externalID string, scope string, config *v3.AzureADConfig) (*v3.Principal, error) {
	principal := &v3.Principal{
		ObjectMeta:  metav1.ObjectMeta{Name: scope + "://" + externalID},
		DisplayName: externalID,
		//PrincipalType: kind,
		Provider: Name,
	}

	//principal := &v3.Principal{
	//	ObjectMeta:    metav1.ObjectMeta{Name: scope + "://" + distinguishedName},
	//	DisplayName:   distinguishedName,
	//	LoginName:     distinguishedName,
	//	PrincipalType: kind,
	//}

	return principal, nil
	//var search *ldapv2.SearchRequest
	//if !slice.ContainsString(scopes, scope) {
	//	return nil, fmt.Errorf("Invalid scope")
	//}
	//
	//var attributes []*ldapv2.AttributeTypeAndValue
	//var attribs []*ldapv2.EntryAttribute
	//object, err := ldapv2.ParseDN(distinguishedName)
	//if err != nil {
	//	return nil, err
	//}
	//for _, rdns := range object.RDNs {
	//	for _, attr := range rdns.Attributes {
	//		attributes = append(attributes, attr)
	//		entryAttr := ldapv2.NewEntryAttribute(attr.Type, []string{attr.Value})
	//		attribs = append(attribs, entryAttr)
	//	}
	//}
	//
	//if !ldap.IsType(attribs, scope) && !ldap.HasPermission(attribs, config) {
	//	logrus.Errorf("Failed to get object %s", distinguishedName)
	//	return nil, nil
	//}
	//
	//filter := "(" + ObjectClassAttribute + "=*)"
	//logrus.Debugf("Query for getPrincipal(%s): %s", distinguishedName, filter)
	//lConn, err := ldap.NewLDAPConn(config, caPool)
	//if err != nil {
	//	return nil, err
	//}
	//defer lConn.Close()
	//// Bind before query
	//// If service acc bind fails, and auth is on, return principal formed using DN
	//serviceAccountUsername := ldap.GetUserExternalID(config.ServiceAccountUsername, config.DefaultLoginDomain)
	//err = lConn.Bind(serviceAccountUsername, config.ServiceAccountPassword)
	//
	//if err != nil {
	//	if ldapv2.IsErrorWithCode(err, ldapv2.LDAPResultInvalidCredentials) && config.Enabled {
	//		var kind string
	//		if strings.EqualFold(UserScope, scope) {
	//			kind = "user"
	//		} else if strings.EqualFold(GroupScope, scope) {
	//			kind = "group"
	//		}
	//		principal := &v3.Principal{
	//			ObjectMeta:    metav1.ObjectMeta{Name: scope + "://" + distinguishedName},
	//			DisplayName:   distinguishedName,
	//			LoginName:     distinguishedName,
	//			PrincipalType: kind,
	//		}
	//
	//		return principal, nil
	//	}
	//	return nil, fmt.Errorf("Error in ldap bind: %v", err)
	//}
	//
	//if strings.EqualFold(UserScope, scope) {
	//	search = ldapv2.NewSearchRequest(distinguishedName,
	//		ldapv2.ScopeWholeSubtree, ldapv2.NeverDerefAliases, 0, 0, false,
	//		filter,
	//		ldap.GetUserSearchAttributes(MemberOfAttribute, ObjectClassAttribute, config), nil)
	//} else {
	//	search = ldapv2.NewSearchRequest(distinguishedName,
	//		ldapv2.ScopeWholeSubtree, ldapv2.NeverDerefAliases, 0, 0, false,
	//		filter,
	//		ldap.GetGroupSearchAttributes(MemberOfAttribute, ObjectClassAttribute, config), nil)
	//}
	//
	//result, err := lConn.Search(search)
	//if err != nil {
	//	return nil, fmt.Errorf("Error %v in search query : %v", err, filter)
	//}
	//
	//if len(result.Entries) < 1 {
	//	return nil, fmt.Errorf("No identities can be retrieved")
	//} else if len(result.Entries) > 1 {
	//	return nil, fmt.Errorf("More than one result found")
	//}
	//
	//entry := result.Entries[0]
	//entryAttributes := entry.Attributes
	//if !ldap.HasPermission(entry.Attributes, config) {
	//	return nil, fmt.Errorf("Permission denied")
	//}
	//
	//principal, err := p.attributesToPrincipal(entryAttributes, distinguishedName, scope, config)
	//if err != nil {
	//	return nil, err
	//}
	//if principal == nil {
	//	return nil, fmt.Errorf("Principal not returned for LDAP")
	//}
	//return principal, nil
}

//func (ac *AzureADClient) attributesToPrincipal(dnStr string, scope string, config *v3.ActiveDirectoryConfig) (*v3.Principal, error) {
//	var externalIDType, accountName, externalID, login, kind string
//	externalID = dnStr
//	externalIDType = scope

//if ldap.IsType(attribs, config.UserObjectClass) {
//	for _, attr := range attribs {
//		if attr.Name == config.UserNameAttribute {
//			if len(attr.Values) != 0 {
//				accountName = attr.Values[0]
//			} else {
//				accountName = externalID
//			}
//		}
//		if attr.Name == config.UserLoginAttribute {
//			login = attr.Values[0]
//		}
//	}
//	kind = "user"
//} else if ldap.IsType(attribs, config.GroupObjectClass) {
//	for _, attr := range attribs {
//		if attr.Name == config.GroupNameAttribute {
//			if len(attr.Values) != 0 {
//				accountName = attr.Values[0]
//			} else {
//				accountName = externalID
//			}
//		}
//		if attr.Name == config.UserLoginAttribute {
//			if len(attr.Values) > 0 && attr.Values[0] != "" {
//				login = attr.Values[0]
//			}
//		} else {
//			login = accountName
//		}
//	}
//	kind = "group"
//} else {
//	logrus.Errorf("Failed to get attributes for %s", dnStr)
//	return nil, nil
//}
//
//	principal := &v3.Principal{
//		ObjectMeta:    metav1.ObjectMeta{Name: externalIDType + "://" + externalID},
//		DisplayName:   accountName,
//		PrincipalType: kind,
//		Provider:      Name,
//	}
//
//	return principal, nil
//}

//func (ac *AzureADClient) searchGroup(name string, config *v3.AzureADConfig) ([]v3.Principal, error) {
//	query := "(&(" + config.GroupSearchAttribute + "=*" + name + "*)(" + ObjectClassAttribute + "=" +
//		config.GroupObjectClass + "))"
//	logrus.Debugf("LDAPProvider searchGroup query: %s", query)
//	return p.searchLdap(query, GroupScope, config, caPool)
//}

//func (ac *AzureADClient) getGroup(azureAccessToken string, config *v3.AzureADConfig) ([]AzureADAccount, error) {
//	var groups []AzureADAccount
//	url, err := ac.getURL("GROUP", config, "")
//	resp, err := ac.getFromAzureAD(azureAccessToken, url)
//	if err != nil {
//		logrus.Errorf("AzureAD getAzureADUser: GET url %v received error from github, err: %v", url, err)
//		return []AzureADAccount{}, err
//	}
//	defer resp.Body.Close()
//	var azureADAcct []AzureADAccount
//
//	b, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		logrus.Errorf("AzureAD getAzureADUser: error reading response, err: %v", err)
//		return []AzureADAccount{}, err
//	}
//
//	if err := json.Unmarshal(b, &azureADAcct); err != nil {
//		logrus.Errorf("AzureAD getAzureADUser: error unmarshalling response, err: %v", err)
//		return []AzureADAccount{}, err
//	}
//	//get list then append to groups
//	return azureADAcct, nil
//}

func (ac *AzureADClient) getFromAzureAD(azureAccessToken string, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+azureAccessToken)
	req.Header.Add("Accept", "application/json")
	resp, err := ac.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("Received error from azure: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (ac *AzureADClient) getURL(endpoint string, config *v3.AzureADConfig, objectId string) (string, error) {
	apiEndpoint := "https://graph.windows.net/"
	tenantId := config.TenantID
	var toReturn string

	switch endpoint {
	case "TOKEN":
		toReturn = "https://login.windows.net/common/oauth2/token"
	case "USERS":
		toReturn = apiEndpoint + tenantId + "/users/" + objectId
	case "GROUPS":
		toReturn = apiEndpoint + tenantId + "/groups/" + objectId
	case "USER":
		toReturn = apiEndpoint + "me"
	case "GROUP":
		toReturn = apiEndpoint + "me/memberof"
	default:
		return "", httperror.NewAPIError(httperror.ServerError, "Azure Client attempted to get invalid Api endpoint")
	}

	return toReturn + "?api-version=1.6", nil
}

func isConfigured(config *v3.AzureADConfig) bool {
	if config.TenantID != "" && config.ClientID != "" && config.Domain != "" {
		return true
	}
	return false
}
