package azuread

type searchResult struct {
	Items []Account `json:"items"`
}

//Account defines properties an account on github has
type Account struct {
	ObjectID          int    `json:"objectId,omitempty"`
	AccountName       string `json:"accountName,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	ThumbNail         string `json:"thumbNail,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
}
