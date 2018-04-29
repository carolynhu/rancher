package azuread

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/rancher/norman/httperror"
	"github.com/rancher/rancher/pkg/auth/providers/common/ldap"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/apis/management.cattle.io/v3public"
	"github.com/sirupsen/logrus"
)

type AzureADClient struct {
	httpClient *http.Client
}

func (p *azureADProvider) loginUser(adCredential *v3public.BasicLogin, config *v3.AzureADConfig) (v3.Principal, []v3.Principal, map[string]string, error) {
	username := adCredential.Username
	password := adCredential.Password
	if password == "" {
		return v3.Principal{}, nil, nil, httperror.NewAPIError(httperror.MissingRequired, "password not provided")
	}
	externalID := ldap.GetUserExternalID(username, config.Domain)

	//if !config.Enabled { // TODO testing for enabled here might not be correct. Might be better to pass in an explicit testSvcAccount bool
	//	logrus.Debug("Bind service account username password")
	//	if config.AdminAccountPassword == "" {
	//		return v3.Principal{}, nil, nil, httperror.NewAPIError(httperror.MissingRequired, "admin account password not provided")
	//	}
	//	adminusername := ldap.GetUserExternalID(config.AdminAccountUsername, config.Domain)
	//	err = lConn.Bind(adminusername, config.AdminAccountPassword)
	//	if err != nil {
	//		if ldapv2.IsErrorWithCode(err, ldapv2.LDAPResultInvalidCredentials) {
	//			return v3.Principal{}, nil, nil, httperror.WrapAPIError(err, httperror.Unauthorized, "authentication failed")
	//		}
	//		return v3.Principal{}, nil, nil, httperror.WrapAPIError(err, httperror.ServerError, "server error while authenticating")
	//	}
	//}

	//logrus.Debug("Binding username password")
	//err = lConn.Bind(externalID, password)
	//if err != nil {
	//	if ldapv2.IsErrorWithCode(err, ldapv2.LDAPResultInvalidCredentials) {
	//		return v3.Principal{}, nil, nil, httperror.WrapAPIError(err, httperror.Unauthorized, "authentication failed")
	//	}
	//	return v3.Principal{}, nil, nil, httperror.WrapAPIError(err, httperror.ServerError, "server error while authenticating")
	//}

	//samName := username
	//if strings.Contains(username, `\`) {
	//	samName = strings.SplitN(username, `\`, 2)[1]
	//}
	//query := "(" + config.UserLoginAttribute + "=" + ldapv2.EscapeFilter(samName) + ")"
	//logrus.Debugf("LDAP Search query: {%s}", query)
	//search := ldapv2.NewSearchRequest(config.UserSearchBase,
	//	ldapv2.ScopeWholeSubtree, ldapv2.NeverDerefAliases, 0, 0, false,
	//	query,
	//	ldap.GetUserSearchAttributes(MemberOfAttribute, ObjectClassAttribute, config), nil)

	userPrincipal, groupPrincipals, err := p.userRecord(search, lConn, config, caPool)
	if err != nil {
		return v3.Principal{}, nil, nil, err
	}

	allowed, err := p.userMGR.CheckAccess(config.AccessMode, config.AllowedPrincipalIDs, userPrincipal, groupPrincipals)
	if err != nil {
		return v3.Principal{}, nil, nil, err
	}
	if !allowed {
		return v3.Principal{}, nil, nil, httperror.NewAPIError(httperror.Unauthorized, "unauthorized")
	}

	return userPrincipal, groupPrincipals, map[string]string{}, err
}

func (ac *AzureADClient) getUser(githubAccessToken string, config *v3.GithubConfig) (Account, error) {

	url := g.getURL("USER_INFO", config)
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		logrus.Errorf("Github getGithubUser: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var githubAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Github getGithubUser: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		logrus.Errorf("Github getGithubUser: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

//func (ac *AzureADClient) getAccessToken(config *v3.AzureADConfig) (string, error) {
//	if isConfigured(config) == false {
//		logrus.Errorf("There are missing fields in AzureAD config")
//		return "", fmt.Errorf("There are missing fields in AzureAD config")
//	}
//
//	form := url.Values{}
//	form.Add("tenant_id", config.TenantID)
//	form.Add("client_id", config.ClientID)
//	form.Add("domain", config.Domain)
//
//	url := ac.getURL("TOKEN", config)
//
//	resp, err := ac.postToAzureAD(url, form)
//	if err != nil {
//		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azuread, err: %v", url, err)
//		return "", err
//	}
//	defer resp.Body.Close()
//
//	// Decode the response
//	var respMap map[string]interface{}
//	b, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		logrus.Errorf("Github getAccessToken: received error reading response body, err: %v", err)
//		return "", err
//	}
//
//	if err := json.Unmarshal(b, &respMap); err != nil {
//		logrus.Errorf("Github getAccessToken: received error unmarshalling response body, err: %v", err)
//		return "", err
//	}
//
//	if respMap["error"] != nil {
//		desc := respMap["error_description"]
//		logrus.Errorf("Received Error from github %v, description from github %v", respMap["error"], desc)
//		return "", fmt.Errorf("Received Error from github %v, description from github %v", respMap["error"], desc)
//	}
//
//	acessToken, ok := respMap["access_token"].(string)
//	if !ok {
//		return "", fmt.Errorf("Received Error reading accessToken from response %v", respMap)
//	}
//	return acessToken, nil
//}
//
//func (ac *AzureADClient) postToAzureAD(url string, form url.Values) (*http.Response, error) {
//	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
//	if err != nil {
//		logrus.Error(err)
//	}
//	req.PostForm = form
//	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
//	req.Header.Add("Accept", "application/json")
//	resp, err := ac.httpClient.Do(req)
//	if err != nil {
//		logrus.Errorf("Received error from github: %v", err)
//		return resp, err
//	}
//	// Check the status code
//	switch resp.StatusCode {
//	case 200:
//	case 201:
//	default:
//		var body bytes.Buffer
//		io.Copy(&body, resp.Body)
//		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
//			resp.StatusCode, body.Bytes())
//	}
//	return resp, nil
//}
//
//func (ac *AzureADClient) getURL(endpoint string, config *v3.AzureADConfig) string {
//	//
//	//var hostName, apiEndpoint, toReturn string
//	//
//	//if config.Hostname != "" {
//	//	scheme := "http://"
//	//	if config.TLS {
//	//		scheme = "https://"
//	//	}
//	//	hostName = scheme + config.Hostname
//	//	if hostName == githubDefaultHostName {
//	//		apiEndpoint = githubAPI
//	//	} else {
//	//		apiEndpoint = scheme + config.Hostname + gheAPI
//	//	}
//	//} else {
//	//	hostName = githubDefaultHostName
//	//	apiEndpoint = githubAPI
//	//}
//	//
//	//switch endpoint {
//	//case "API":
//	//	toReturn = apiEndpoint
//	//case "TOKEN":
//	//	toReturn = hostName + "/login/oauth/access_token"
//	//case "USERS":
//	//	toReturn = apiEndpoint + "/users/"
//	//case "ORGS":
//	//	toReturn = apiEndpoint + "/orgs/"
//	//case "USER_INFO":
//	//	toReturn = apiEndpoint + "/user"
//	//case "ORG_INFO":
//	//	toReturn = apiEndpoint + "/user/orgs?per_page=1"
//	//case "USER_PICTURE":
//	//	toReturn = "https://avatars.githubusercontent.com/u/" + endpoint + "?v=3&s=72"
//	//case "USER_SEARCH":
//	//	toReturn = apiEndpoint + "/search/users?q="
//	//case "TEAM":
//	//	toReturn = apiEndpoint + "/teams/"
//	//case "TEAMS":
//	//	toReturn = apiEndpoint + "/user/teams?per_page=100"
//	//case "TEAM_PROFILE":
//	//	toReturn = hostName + "/orgs/%s/teams/%s"
//	//default:
//	//	toReturn = apiEndpoint
//	//}
//	//
//	//return toReturn
//	return "http://"
//}
//
//func isConfigured(config *v3.AzureADConfig) bool {
//	if config.TenantID != "" && config.ClientID != "" && config.Domain != "" {
//		return true
//	}
//	return false
//}
