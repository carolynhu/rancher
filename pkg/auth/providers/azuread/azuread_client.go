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
)

const (
	AzureURIChina          = ".chinacloudapi.cn"
	AzureURIGerman         = ".microsoftonline.de"
	AzureURIGlobal         = ".windows.net"
	AuthorityChina         = "https://login" + AzureURIChina + "/common/oauth2/token"
	AuthorityGerman        = "https://login" + AzureURIGerman + "/common/oauth2/token"
	AuthorityGlobal        = "https://login" + AzureURIGlobal + "/common/oauth2/token"
	GraphAPIEndpointChina  = "https://graph" + AzureURIChina
	GraphAPIEndpointGerman = "https://graph" + AzureURIGerman
	GraphAPIEndpointGlobal = "https://graph" + AzureURIGlobal
	GraphAPIVersion        = "?api-version=1.6"
	BodyConstruct          = "scope=openid&grant_type=password&resource=https%3A%2F%2F"
)

type Client struct {
	httpClient *http.Client
}

func (ac *Client) uriEndpointConstruction(config *v3.AzureADConfig) (string, string, string, error) {
	var authority, graphEndpoint, bodyconstruct string
	domain := config.Domain
	if strings.Contains(domain, "partner.onmschina.cn") {
		authority = AuthorityChina
		graphEndpoint = GraphAPIEndpointChina
		bodyconstruct = BodyConstruct + "graph" + AzureURIChina
	} else if strings.Contains(domain, "onmicrosoft.de") {
		authority = AuthorityGerman
		graphEndpoint = GraphAPIEndpointGerman
		bodyconstruct = BodyConstruct + "graph" + AzureURIGerman
	} else if strings.Contains(domain, "onmicrosoft.com") {
		authority = AuthorityGlobal
		graphEndpoint = GraphAPIEndpointGlobal
		bodyconstruct = BodyConstruct + "graph" + AzureURIGlobal
	} else {
		return "", "", "", fmt.Errorf("Wrong Azure Domain %v is provided", domain)
	}
	return authority, graphEndpoint, bodyconstruct, nil
}

func (ac *Client) getAccessToken(adCredential *v3public.BasicLogin, config *v3.AzureADConfig) (string, string, error) {
	if ac.isConfigured(config) == false {
		return "", "", httperror.NewAPIError(httperror.ServerError, "Azure Client is not configured")
	}

	username := adCredential.Username
	password := adCredential.Password
	if username == "" || password == "" {
		return "", "", httperror.NewAPIError(httperror.MissingRequired, "username or password not provided")
	}

	domain := config.Domain
	endsWith := strings.HasSuffix("username", "@"+domain)
	if domain != "" && endsWith == false {
		username = username + "%40" + domain //"@" is encoded to "%40"
	}

	authority, graphEndpoint, bodyconstruct, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", domain)
		return "", "", fmt.Errorf("Wrong Azure Domain %v is provided", domain)
	}
	body := bytes.Buffer{}
	body.WriteString(bodyconstruct)
	body.WriteString("&client_id=")
	body.WriteString(config.ClientID)
	body.WriteString("&client_secret=")
	body.WriteString(config.ClientSecret) //ClientSecret is a required field for China AzureAD
	body.WriteString("&username=")
	body.WriteString(username)
	body.WriteString("&password=")
	body.WriteString(password)

	url, err := ac.getURL(authority, graphEndpoint, "TOKEN", config, "")
	if err != nil {
		logrus.Errorf("AzureAD GET url %v received error from Azure, err: %v", url, err)
		return "", "", err
	}

	resp, err := ac.postToAzureAD(url, body.String())
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from Azure, err: %v", url, err)
		return "", "", err
	}
	defer resp.Body.Close()

	// Decode the response
	var respMap map[string]interface{}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error reading response body, err: %v", err)
		return "", "", err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", "", err
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		logrus.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
		return "", "", fmt.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
	}

	accessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}

	refreshToken, ok := respMap["refresh_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Received Error reading refreshToken from response %v", respMap)
	}
	return accessToken, refreshToken, nil
}

func (ac *Client) postToAzureAD(url string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		logrus.Error(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

func (ac *Client) getUser(azureAccessToken string, config *v3.AzureADConfig) (Account, map[string]string, error) {
	if azureAccessToken == "" {
		return Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}

	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}
	url, err := ac.getURL(authority, graphEndpoint, "USER", config, "")

	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: GET url %v received error from Azure, err: %v", url, err)
		return Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return Account{}, nil, err
		}
	}
	defer resp.Body.Close()
	var azureADAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error reading response, err: %v", err)
		return Account{}, nil, err
	}

	if err := json.Unmarshal(b, &azureADAcct); err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error unmarshalling response, err: %v", err)
		return Account{}, nil, err
	}

	return azureADAcct, providerInfo, nil
}

func (ac *Client) getGroups(azureAccessToken string, config *v3.AzureADConfig) ([]Account, map[string]string, error) {
	if azureAccessToken == "" {
		return []Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}
	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return []Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}
	url, err := ac.getURL(authority, graphEndpoint, "GROUP", config, "")

	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: GET url %v received error from Azure, err: %v", url, err)
		return []Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return []Account{}, nil, err
		}
	}
	defer resp.Body.Close()
	result := &searchResult{}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: error reading response, err: %v", err)
		return []Account{}, nil, err
	}

	if err := json.Unmarshal(b, result); err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: error unmarshalling response, err: %v", err)
		return []Account{}, nil, err
	}

	return result.Items, providerInfo, nil
}

func (ac *Client) searchUsers(searchkey string, azureAccessToken string, config *v3.AzureADConfig) ([]Account, map[string]string, error) {
	if azureAccessToken == "" {
		return []Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}
	if searchkey == "" {
		return nil, nil, httperror.NewAPIError(httperror.ServerError, "No azure username specified")
	}
	filter := "$filter=startswith(userPrincipalName,'" + searchkey + "')"

	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return []Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}

	url, err := ac.getURL(authority, graphEndpoint, "USERS", config, "")
	if err != nil {
		logrus.Errorf("AzureAD GET url %v received error from azure, err: %v", url, err)
		return nil, nil, err
	}

	url = url + "&" + filter
	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
		return []Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return []Account{}, nil, err
		}
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	result := &searchResult{}
	if err := json.Unmarshal(b, result); err != nil {
		return nil, nil, err
	}
	return result.Items, providerInfo, nil
}

func (ac *Client) searchGroups(searchkey string, azureAccessToken string, config *v3.AzureADConfig) ([]Account, map[string]string, error) {
	if azureAccessToken == "" {
		return []Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}

	if searchkey == "" {
		return nil, nil, httperror.NewAPIError(httperror.ServerError, "No azure groupname specified")
	}

	filter := "$filter=startswith(displayName,'" + searchkey + "')"

	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return []Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}

	url, err := ac.getURL(authority, graphEndpoint, "GROUPS", config, "")
	if err != nil {
		logrus.Errorf("AzureAD GET url %v received error from azure, err: %v", url, err)
		return nil, nil, err
	}

	url = url + "&" + filter
	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
		return []Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return []Account{}, nil, err
		}
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	result := &searchResult{}
	if err := json.Unmarshal(b, result); err != nil {
		return nil, nil, err
	}
	return result.Items, providerInfo, nil
}

func (ac *Client) getUserByID(id string, azureAccessToken string, config *v3.AzureADConfig) (Account, map[string]string, error) {
	if azureAccessToken == "" {
		return Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}
	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}

	url, err := ac.getURL(authority, graphEndpoint, "USERS", config, id)

	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: GET url %v received error from Azure, err: %v", url, err)
		return Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return Account{}, nil, err
		}
	}
	defer resp.Body.Close()
	var azureADAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error reading response, err: %v", err)
		return Account{}, nil, err
	}

	if err := json.Unmarshal(b, &azureADAcct); err != nil {
		logrus.Errorf("AzureAD getAzureADUser: error unmarshalling response, err: %v", err)
		return Account{}, nil, err
	}

	return azureADAcct, providerInfo, nil
}

func (ac *Client) getGroupByID(id string, azureAccessToken string, config *v3.AzureADConfig) (Account, map[string]string, error) {
	if azureAccessToken == "" {
		return Account{}, nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}
	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return Account{}, nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}

	url, err := ac.getURL(authority, graphEndpoint, "GROUPS", config, id)

	resp, newAccessToken, providerInfo, err := ac.getFromAzureAD(azureAccessToken, config, url)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: GET url %v received error from Azure, err: %v", url, err)
		return Account{}, nil, err
	}
	if newAccessToken != "" {
		resp, _, providerInfo, err = ac.getFromAzureAD(newAccessToken, config, url)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: GET url %v received error from azure, err: %v", url, err)
			return Account{}, nil, err
		}
	}
	defer resp.Body.Close()

	var azureADAcct Account
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: error reading response, err: %v", err)
		return Account{}, nil, err
	}

	if err := json.Unmarshal(b, &azureADAcct); err != nil {
		logrus.Errorf("AzureAD getAzureADGroup: error unmarshalling response, err: %v", err)
		return Account{}, nil, err
	}

	return azureADAcct, providerInfo, nil
}

func (ac *Client) getFromAzureAD(azureAccessToken string, config *v3.AzureADConfig, url string) (*http.Response, string, map[string]string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+azureAccessToken)
	req.Header.Add("Accept", "application/json")
	resp, err := ac.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("Received error from azure: %v", err)
		return resp, "", nil, err
	}

	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		//determine whether the access_token has expired, if so, refresh it
		var respMap map[string]interface{}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Errorf("AzureAD getAccessToken: received error reading response body, err: %v", err)
			return resp, "", nil, err
		}
		if err := json.Unmarshal(b, &respMap); err != nil {
			logrus.Errorf("AzureAD getAccessToken: received error unmarshalling response body, err: %v", err)
			return resp, "", nil, err
		}
		if respMap["odata.error"] != nil {
			odataError := respMap["odata.error"].(map[string]interface{})
			azureCode := odataError["code"].(string)
			if strings.EqualFold("Authentication_ExpiredToken", azureCode) {
				newAccessToken, providerInfo, err := ac.refreshAccessToken(respMap, config)
				if err != nil {
					logrus.Errorf("AzureAD refresh AccessToken received error: %v", err)
					return resp, "", nil, err
				}
				return resp, newAccessToken, providerInfo, err
			}
		}

		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, "", nil, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, "", nil, nil
}

func (ac *Client) getURL(authority string, graphEndPoint string, azureClientEndpoint string, config *v3.AzureADConfig, objectID string) (string, error) {
	apiEndpoint := graphEndPoint
	tenantID := config.TenantID
	var toReturn string

	switch azureClientEndpoint {
	case "TOKEN":
		return authority, nil
	case "USER":
		toReturn = apiEndpoint + "/me"
	case "GROUP":
		toReturn = apiEndpoint + "/me/memberOf"
	case "USERS":
		toReturn = apiEndpoint + "/" + tenantID + "/users/" + objectID
	case "GROUPS":
		toReturn = apiEndpoint + "/" + tenantID + "/groups/" + objectID
	default:
		return "", httperror.NewAPIError(httperror.ServerError, "Azure Client attempted to get invalid Api endpoint")
	}

	return toReturn + GraphAPIVersion, nil
}

func (ac *Client) isConfigured(config *v3.AzureADConfig) bool {
	if config.TenantID != "" && config.ClientID != "" && config.Domain != "" {
		return true
	}
	return false
}

func (ac *Client) refreshAccessToken(respMap map[string]interface{}, config *v3.AzureADConfig) (string, map[string]string, error) {
	var providerInfo = make(map[string]string)
	_, ok := respMap["access_token"].(string)
	if !ok {
		return "", nil, httperror.NewAPIError(httperror.ServerError, "No Azure Access token")
	}
	refreshToken, ok := respMap["refresh_token"].(string)
	if !ok {
		return "", nil, httperror.NewAPIError(httperror.ServerError, "No Azure Refresh token")
	}

	authority, graphEndpoint, _, err := ac.uriEndpointConstruction(config)
	if err != nil {
		logrus.Errorf("Wrong Azure Domain %v is provided", config.Domain)
		return "", nil, fmt.Errorf("Wrong Azure Domain %v is provided", config.Domain)
	}
	body := bytes.Buffer{}
	body.WriteString("grant_type=refresh_token&refresh_token=" + refreshToken)

	url, err := ac.getURL(authority, graphEndpoint, "TOKEN", config, "")
	if err != nil {
		logrus.Errorf("AzureAD GET url %v received error from Azure, err: %v", url, err)
		return "", nil, err
	}

	resp, err := ac.postToAzureAD(url, body.String())
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: GET url %v received error from Azure, err: %v", url, err)
		return "", nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error reading response body, err: %v", err)
		return "", nil, err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		logrus.Errorf("AzureAD getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", nil, err
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		logrus.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
		return "", nil, fmt.Errorf("Received Error from AzureAD %v, description from AzureAD %v", respMap["error"], desc)
	}
	newAccessToken := respMap["access_token"]
	providerInfo["access_token"] = newAccessToken.(string) //update access_token

	return newAccessToken.(string), providerInfo, nil
}
