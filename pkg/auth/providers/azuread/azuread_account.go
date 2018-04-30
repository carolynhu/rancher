package azuread

type searchResult struct {
	Items []AzureADAccount `json:"items"`
}

//Account defines properties an account on github has
type AzureADAccount struct {
	ObjectID          int    `json:"objectId,omitempty"`
	Name              string `json:"name,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	ThumbNail         string `json:"thumbNail,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
}
