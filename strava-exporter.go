package main

import (
	"fmt"
	"net/http"
	"encoding/json"
	"os"
	"log"
	"strings"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/trentdavies/go.strava" //fork of strava/go.strava
	"github.com/motemen/go-loghttp"
)

const port = 8080

var authenticator *strava.OAuthAuthenticator

const (
	ConfKeyClientId     string = "client-id"
	ConfKeyClientSecret string = "client-secret"
	ConfKeyAthleteId    string = "athlete-id"
	ConfKeyAccessToken  string = "token"
	ConfEnvPrefix       string = "STRAVA"
)

func init() {
	//allows us to use ENV and cli flags interchangeably/**/
	viper.SetEnvPrefix(ConfEnvPrefix)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func main() {
	cmd := NewStravaImporterCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

/* Compute the env config name for use in usage/help */
func envConfigNameHelp(cli_flag string) string {
	o := strings.ToUpper(fmt.Sprintf("%s_%s", ConfEnvPrefix, strings.Replace(cli_flag, "-", "_", -1)))
	return fmt.Sprintf("Also settable as env variable: '%s'", o)
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
		fmt.Printf("%s is undefined", ConfKeyAthleteId)
		os.Exit(1)
	}
	return athleteId
}

func stravaClient(debug bool) *strava.Client {
	var httpClient *http.Client
	if debug {
		httpClient = &http.Client{
			Transport: &loghttp.Transport{},
		}
	} else {
		httpClient = http.DefaultClient
	}

	client := strava.NewClient(accessToken(), httpClient)
	return client
}

func NewStravaImporterCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "strava-exporter",
		Short:   "Interacts with the Strava API",
		Long:    "",
		Example: "",
		Run:     nil, //output help
	}
	rootCmd.PersistentFlags().String(ConfKeyAccessToken, "", fmt.Sprintf("Strava API Token. "+envConfigNameHelp(ConfKeyAccessToken)))
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "enable debug output")
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Retrieve API access token for future calls via web OAuth workflow",
		Long:  `Starts a webserver that, when accessed in the browser, will authenticate against the Strava API`,
		Run:   authenticate,
	}
	authCmd.PersistentFlags().Int(ConfKeyClientId, 0, "Strava Client ID. "+envConfigNameHelp(ConfKeyClientId))
	authCmd.PersistentFlags().String(ConfKeyClientSecret, "", "Strava Client Secret. "+envConfigNameHelp(ConfKeyClientSecret))
	rootCmd.AddCommand(authCmd)
	getCmd := &cobra.Command{
		Use:   "get [activity id]",
		Short: "Get a detailed activity",
		Args:  cobra.ExactArgs(1),
		Run:   getActivity,
	}
	getCmd.PersistentFlags().BoolP("include-all","a", false, "include all efforts")
	rootCmd.AddCommand(getCmd)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list athlete activities",
		Run:   listActivities,
	}
	listCmd.PersistentFlags().Int(ConfKeyAthleteId, 0, "Strava Athlete id for associated calls. "+envConfigNameHelp(ConfKeyAthleteId))
	rootCmd.AddCommand(listCmd)
	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(listCmd.PersistentFlags())
	viper.BindPFlags(authCmd.PersistentFlags())
	viper.BindPFlags(getCmd.PersistentFlags())
	return rootCmd
}

func authenticate(c *cobra.Command, args [] string) {
	clientId := viper.GetInt(ConfKeyClientId)
	strava.ClientId = clientId
	clientSecret := viper.GetString(ConfKeyClientSecret)
	strava.ClientSecret = clientSecret
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

//type stravaData struct {
//	summary *strava.ActivitySummary
//}

func listActivities(c *cobra.Command, args []string) {
	//log.Println("listActivities")
	athleteId := athleteId()
	client := stravaClient(viper.GetBool("debug"))
	results, err := strava.NewAthletesService(client).ListActivities(athleteId).Do()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, r := range results {
		//content, _ := json.MarshalIndent(r, "", " ")
		//content, _ := json.Marshal(r)
		//activity := activityDetails(client, r)
		//activityContent, _ := json.Marshal(activity)
		fmt.Println(r.Id, r.Name)
		//fmt.Println(string(activityContent))
		//fmt.Println(r.Id, r.Name, string(content))
	}
}

func getActivity(c *cobra.Command, args []string) {
	includeAll := viper.GetBool("include-all")
	activityId, _ := strconv.ParseInt(args[0], 10, 64)
	client := stravaClient(viper.GetBool("debug"))
	s := strava.NewActivitiesService(client).Get(activityId)
	if includeAll {
		s.IncludeAllEfforts()
	}
	result, err := s.Do()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	content, _ := json.MarshalIndent(result, "", " ")
	fmt.Println(string(content))
}

func activityDetails(client *strava.Client, a *strava.ActivitySummary) *strava.ActivityDetailed {
	result, err := strava.NewActivitiesService(client).Get(a.Id).IncludeAllEfforts().Do()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return result
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
