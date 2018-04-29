package azuread

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/rancher/types/user"

	"strings"

	"net/http"

	"github.com/rancher/types/apis/management.cattle.io/v3public"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	Name                 = "azuread"
	UserScope            = Name + "_user"
	GroupScope           = Name + "_group"
	MemberOfAttribute    = "memberOf"
	ObjectClassAttribute = "objectClass"
)

var scopes = []string{UserScope, GroupScope}

type azureADProvider struct {
	ctx           context.Context
	authConfigs   v3.AuthConfigInterface
	azureADClient *AzureADClient
	userMGR       user.Manager
}

func Configure(ctx context.Context, mgmtCtx *config.ScaledContext, userMGR user.Manager) common.AuthProvider {
	azureADClient := &AzureADClient{
		httpClient: &http.Client{},
	}
	return &azureADProvider{
		ctx:           ctx,
		authConfigs:   mgmtCtx.Management.AuthConfigs(""),
		azureADClient: azureADClient,
		userMGR:       userMGR,
	}
}

func (p *azureADProvider) GetName() string {
	return Name
}

func (p *azureADProvider) CustomizeSchema(schema *types.Schema) {
	schema.ActionHandler = p.actionHandler
	schema.Formatter = p.formatter
}

func (p *azureADProvider) TransformToAuthProvider(authConfig map[string]interface{}) map[string]interface{} {
	azureADP := common.TransformToAuthProvider(authConfig)
	return azureADP
}

func (p *azureADProvider) AuthenticateUser(input interface{}) (v3.Principal, []v3.Principal, map[string]string, error) {
	login, ok := input.(*v3public.BasicLogin)
	if !ok {
		return v3.Principal{}, nil, nil, errors.New("unexpected input type")
	}

	config, err := p.getAzureADConfig()
	if err != nil {
		return v3.Principal{}, nil, nil, errors.New("can't find authprovider")
	}

	return p.loginUser(login, config)
}
func (p *azureADProvider) SearchPrincipals(searchKey, principalType string, myToken v3.Token) ([]v3.Principal, error) {
	var principals []v3.Principal
	var err error

	// TODO use principalType in search
	config, err := p.getAzureADConfig()
	if err != nil {
		return principals, nil
	}

	principals, err = p.searchPrincipals(searchKey, principalType, config)
	if err == nil {
		for _, principal := range principals {
			if principal.PrincipalType == "user" {
				if p.isThisUserMe(myToken.UserPrincipal, principal) {
					principal.Me = true
				}
			} else if principal.PrincipalType == "group" {
				if p.isMemberOf(myToken.GroupPrincipals, principal) {
					principal.MemberOf = true
				}
			}
		}
	}

	return principals, nil
}

func (p *azureADProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	config, err := p.getAzureADConfig()
	if err != nil {
		return v3.Principal{}, nil
	}

	parts := strings.SplitN(principalID, ":", 2)
	if len(parts) != 2 {
		return v3.Principal{}, errors.Errorf("invalid id %v", principalID)
	}
	scope := parts[0]
	externalID := strings.TrimPrefix(parts[1], "//")

	principal, err := p.getPrincipal(externalID, scope, config)
	if err != nil {
		return v3.Principal{}, err
	}
	if p.isThisUserMe(token.UserPrincipal, *principal) {
		principal.Me = true
	}
	return *principal, err
}

func (p *azureADProvider) isThisUserMe(me v3.Principal, other v3.Principal) bool {
	if me.ObjectMeta.Name == other.ObjectMeta.Name && me.LoginName == other.LoginName && me.PrincipalType == other.PrincipalType {
		return true
	}
	return false
}

func (p *azureADProvider) isMemberOf(myGroups []v3.Principal, other v3.Principal) bool {
	for _, mygroup := range myGroups {
		if mygroup.ObjectMeta.Name == other.ObjectMeta.Name && mygroup.PrincipalType == other.PrincipalType {
			return true
		}
	}
	return false
}

func (p *azureADProvider) getAzureADConfig() (*v3.AzureADConfig, error) {
	authConfigObj, err := p.authConfigs.ObjectClient().UnstructuredClient().Get(Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AzureADConfig, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve AzureADConfig, cannot read k8s Unstructured data")
	}
	storedAzureADConfigMap := u.UnstructuredContent()

	storedAzureADConfig := &v3.AzureADConfig{}
	mapstructure.Decode(storedAzureADConfigMap, storedAzureADConfig)

	metadataMap, ok := storedAzureADConfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to retrieve AzureADConfig metadata, cannot read k8s Unstructured data")
	}

	typemeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, typemeta)
	storedAzureADConfig.ObjectMeta = *typemeta

	return storedAzureADConfig, nil
}

//func (p *azureADProvider) loginUser(azureADCdredential *v3public.BasicLogin, azureADConfig *v3.AzureADConfig) (v3.Principal, []v3.Principal, map[string]string, error) {
//	//var userPrincipal v3.Principal
//	var providerInfo = make(map[string]string)
//	var err error
//
//	if azureADConfig == nil {
//		azureADConfig, err = p.getAzureADConfig()
//		if err != nil {
//			return v3.Principal{}, nil, nil, err
//		}
//	}
//
//	accessToken, err := p.azureADClient.getAccessToken(azureADConfig)
//	if err != nil {
//		logrus.Infof("Error generating accessToken from azuread %v", err)
//		return v3.Principal{}, nil, nil, err
//	}
//	logrus.Debugf("Received AccessToken from azuread %v", accessToken)
//
//	providerInfo["access_token"] = accessToken
//
//	//user, err := p.azureADClient.getUser(accessToken, azureADConfig)
//	//if err != nil {
//	//	return v3.Principal{}, nil, nil, err
//	//}
//	//userPrincipal = p.toPrincipal(userType, user, nil)
//	//userPrincipal.Me = true
//
//}
