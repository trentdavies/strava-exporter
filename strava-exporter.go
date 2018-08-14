package main

import (
	"fmt"
	"net/http"
	"encoding/json"
	"os"
	"log"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trentdavies/go.strava" //fork of strava/go.strava
	"github.com/spf13/viper"
)

const port = 8080

var authenticator *strava.OAuthAuthenticator

const (
	ConfKeyClientId     string = "client-id"
	ConfKeyClientSecret string = "client-secret"
	ConfKeyAthleteId    string = "athlete-id"
	ConfKeyAccessToken  string = "token"
	ConfEnvPrefix string = "STRAVA"
)

func init() {
	//allows us to use ENV and cli flags interchangeably
	viper.SetEnvPrefix(ConfEnvPrefix)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	//needed for authenticate workflow
	strava.ClientId = viper.GetInt(ConfKeyClientId)
	strava.ClientSecret = viper.GetString(ConfKeyClientSecret)
}

func main() {
	cmd := NewStravaImporterCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

/* Compute the env config name for use in usage/help */
func envConfigName(cli_flag string) string {
	return strings.ToUpper(fmt.Sprintf("%s_%s", ConfEnvPrefix, strings.Replace(cli_flag, "-", "_", -1)))
}

func accessToken() string {
	token := viper.GetString(ConfKeyAccessToken)
	if len(token) == 0 {
		fmt.Println("access token undefined")
		os.Exit(1)
	}
	return token;
}

func athleteId() int64 {
	athleteId := viper.GetInt64(ConfKeyAthleteId)
	if athleteId == 0 {
		fmt.Println()
		os.Exit(1)
	}
	return athleteId
}

func NewStravaImporterCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "strava-exporter",
		Short:   "Interacts with the Strava API",
		Long:    "",
		Example: "",
		Run:     nil, //output help
	}
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Retrieve API access token for future calls via web OAuth workflow",
		Long:  `Starts a webserver that, when accessed in the browser, will authenticate against the Strava API`,
		Run:   authenticate,
	}
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list athlete activities",
		Run:   listActivities,
	}
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.PersistentFlags().String(ConfKeyAccessToken, "", "Strava access token for use with api calls. Set in env with " + envConfigName(ConfKeyAccessToken))
	listCmd.PersistentFlags().Int(ConfKeyAthleteId,0, "Strava athlete id for associated calls. Set in env with " + envConfigName(ConfKeyAthleteId))
	authCmd.PersistentFlags().Int(ConfKeyClientId, 0, "Strava Client ID. Set in env with " + envConfigName(ConfKeyClientId))
	authCmd.PersistentFlags().String(ConfKeyClientSecret, "", "Strava Client Secret. Set in env with " + envConfigName(ConfKeyClientSecret))
	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(listCmd.PersistentFlags())
	viper.BindPFlags(authCmd.PersistentFlags())
	return rootCmd
}

func authenticate(c *cobra.Command, args [] string) {
	// define a strava.OAuthAuthenticator to hold state.
	// The callback url is used to generate an AuthorizationURL.
	// The RequestClientGenerator can be used to generate an http.RequestClient.
	// This is usually when running on the Google App Engine platform.
	authenticator = &strava.OAuthAuthenticator{
		CallbackURL:            fmt.Sprintf("http://localhost:%d/exchange_token", port),
		RequestClientGenerator: nil,
	}

	http.HandleFunc("/", indexHandler)

	path, err := authenticator.CallbackPath()
	if err != nil {
		// possibly that the callback url set above is invalid
		fmt.Println(err)
		os.Exit(1)
	}
	http.HandleFunc(path, authenticator.HandlerFunc(oAuthSuccess, oAuthFailure))

	// start the server
	fmt.Printf("Visit http://localhost:%d/\n", port)
	fmt.Printf("ctrl-c to exit")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func listActivities(c *cobra.Command, args []string) {
	log.Println("listActivities")
	accessToken := accessToken()
	athleteId := athleteId()
	client := strava.NewClient(accessToken)
	results, err := strava.NewAthletesService(client).ListActivities(athleteId).Do()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, r := range results {
		//content, _ := json.MarshalIndent(r, "", " ")
		//content, _ := json.Marshal(r)
		fmt.Println(r.Id, r.Name)
		//fmt.Println(r.Id, r.Name, string(content))
	}
}


func indexHandler(w http.ResponseWriter, r *http.Request) {
	// you should make this a template in your real application
	fmt.Fprintf(w, `<a href="%s">`, authenticator.AuthorizationURL("state1", strava.Permissions.ViewPrivate, true))
	fmt.Fprintf(w, `Authorize My Application`)
	fmt.Fprint(w, `</a>`)
}

func oAuthSuccess(auth *strava.AuthorizationResponse, w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "SUCCESS\n")
	fmt.Fprintf(w, "State: %s\n\n", auth.State)
	fmt.Fprintf(w, "Access Token: %s\n\n", auth.AccessToken)

	fmt.Fprintf(w, "The Authenticated Athlete (you):\n")
	content, _ := json.MarshalIndent(auth.Athlete, "", " ")
	fmt.Fprint(w, string(content))
}

func oAuthFailure(err error, w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Authorization Failure:\n")

	// some standard error checking
	if err == strava.OAuthAuthorizationDeniedErr {
		fmt.Fprint(w, "The user clicked the 'Do not Authorize' button on the previous page.\n")
	} else if err == strava.OAuthInvalidCredentialsErr {
		fmt.Fprint(w, "You provided an incorrect client_id or client_secret.\nDid you remember to set them at the begininng of this file?")
	} else if err == strava.OAuthInvalidCodeErr {
		fmt.Fprint(w, "The temporary token was not recognized, this shouldn't happen normally")
	} else if err == strava.OAuthServerErr {
		fmt.Fprint(w, "There was some sort of server error, try again to see if the problem continues")
	} else {
		fmt.Fprint(w, err)
	}
}
