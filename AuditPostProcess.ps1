$global:RiskyAccounts = @()

function Get-OldPwdAccounts {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [int]$Years,

        [Parameter(Mandatory=$false,Position=2)]
        [string]$OutputCsv,

        [Parameter(Mandatory=$false,Position=3)]
        [array]$Domains,

        [Parameter(Mandatory=$false,Position=4)]
        [switch]$AllTrusts,

        [Parameter(Mandatory=$false,Position=5)]
        [array]$ADProperties = @('SamAccountName','LastLogonDate','PasswordLastSet','PasswordExpired','PasswordNeverExpires','ServicePrincipalNames','SIDHistory','adminCount')
    )

    Begin{
        $pwdDate = (Get-Date).AddYears(-$Years)
        #always want to add this so we can extract domain
        $ADProperties += "CanonicalName"
        $trusts = @()
        if($AllTrusts){
            $trusts = Get-AllADDomains
        }
        else{
            if($null -eq $Domains){
                Write-Verbose "No domains specified, getting current domain"
                $trusts += (Get-ADDomain).name
            }
            else{
                Write-Verbose "Continuing with domains specified by name"
                $trusts = $Domains
            }
        }
        $AllUsers = @()
        Write-Verbose ("Collecting the following AD properties:`n{0}" -f ($ADProperties -join ", "))
        foreach($trust in $trusts){
            Write-Information -MessageData "Gathering users for $trust" -InformationAction Continue
            # could increase efficiency by doing password date comparison here
            # the funky select object will give us a derived domain name, comes in to play when there are multiple
            $AllUsers += (Get-ADUser -Filter "Enabled -eq 'True'" -Server $trust -Properties $ADProperties |
            Select-Object ($ADProperties+@{Name="Domain";Expression={$_.CanonicalName.split("/")[0]}}))
        }
    }

    Process{
        $i = 0
        Write-Information -MessageData "Iterating all users collected, filtering any account with a PwdLastSet date after $passwordDate.`nThis may take some time..." -InformationAction Continue
        foreach($user in $AllUsers){
            $passwordDate = $user.PasswordLastSet
            if($null -ne $passwordDate -and $passwordDate -lt $pwdDate -and ($passwordDate.ToShortDateString() -ne '12/31/1600')){
                #spns have to be iterated to be readable
                $spnList = ''
                if($null -ne $user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0){
                    foreach($spn in [array]$user.ServicePrincipalNames){
                        $spnList += "$spn`n"
                    }
                    $user.ServicePrincipalNames = $spnList
                }
                #dynamically create properties array
                $properties = @{}
                foreach($property in (get-member -InputObject $user -MemberType NoteProperty).Name){
                    $properties.Add("$property",$user.$property)
                }
                $global:RiskyAccounts += New-Object psobject -Property $properties
            }
            if(!($i % 500)){
                $filteredCount = $i - $global:RiskyAccounts.count
                Write-Progress -Activity "Filtering out users..." -Status "Fitlered $filteredCount of $($AllUsers.count)" -PercentComplete (($i / $AllUsers.count) * 100)
            }
            $i++
        }
    }

    End{ 
        WriteSuccess -InputObject "Processing complete : AD accounts with aged passwords"
        if($null -ne $OutputCsv -and $OutputCsv.length -gt 1){
            Write-Information -MessageData "Outputting to $OutputCsv" -InformationAction Continue
            foreach($user in $global:RiskyAccounts){Export-Csv -Path $OutputCsv -InputObject $user -NoTypeInformation -Append}
        }
        else{
            return $global:RiskyAccounts
        }
    }
}

function Invoke-PreemptEnrichment {
    param(
    [Parameter(Mandatory=$true,position=1)]
    [array]$AgedAccounts,

    [Parameter(Mandatory=$true,position=2)]
    [array]$CrackedAccounts,

    [Parameter(Mandatory=$false,Position=3)]
    [securestring]$ApiKey,

    [Parameter(Mandatory=$false,position=4)]
    [string]$OutputCsv,

    [Parameter(Mandatory=$true,position=5)]
    [string]$PreemptUri
    )
    Begin{
        if($null -eq $ApiKey){
            $ApiKey = Read-Host -Prompt "Enter Preempt API key" -AsSecureString 
        }
        $headers = @{"Content-Type"="application/json"; "Authorization"=("Bearer " + (New-Object PSCredential "user",$ApiKey).GetNetworkCredential().Password)}
    }
    Process{
        Write-Information -MessageData "Correlating cracked accounts and retrieving preempt enrichment.`
        `nThis will take some time..." -InformationAction Continue
        $i = 0
        foreach($user in $AgedAccounts){
            # this piece is horribly inefficient... would like to do that intersection better
            if(($CrackedAccounts | Where-Object {$_.SamAccountName -eq $user.SamAccountName -and $_.Domain -eq $user.Domain}).count -ne 0){
                $wasCracked = $true
                Write-Verbose ("{0,-50} was cracked" -f $user.SamAccountName)
            }
            else{
                $wasCracked = $false
                Write-Verbose ("{0,-50} was not cracked" -f $user.SamAccountName)
            }
            #currently, only GA is in preempt
            $username = $user.SamAccountName 
            $domain = $user.Domain
            $riskQuery = "{entities(samAccountNames: `"$username`" domains: `"$domain`" archived: false first: 1){nodes{entityId primaryDisplayName secondaryDisplayName roles {type} ... on UserOrEndpointEntity {riskScore}}}}"
            $riskBody = @{"query"=$riskQuery}
            $authenticationsQuery = "{timeline(types: [SUCCESSFUL_AUTHENTICATION,FAILED_AUTHENTICATION] startTime: `"P-1W`" activityQuery: {authenticationTypes: [DOMAIN_LOGIN]} sourceEntityQuery: {samAccountNames:[`"$username`"] `
            domains:[`"$domain`"]} sortOrder: DESCENDING first: 5) {nodes { ... on TimelineUserOnEndpointActivityEvent {timestamp userEntity{primaryDisplayName roles{type}} endpointEntity {primaryDisplayName} ipAddress deviceType}}}}"
            $authenticationsBody = @{"query"=$authenticationsQuery}
            $preemptRiskResponse = Invoke-RestMethod -Method Post -Headers $headers -Uri $PreemptUri -Body (ConvertTo-Json $riskBody)
            $preemptAuthenticationsResponse = Invoke-RestMethod -Method Post -Headers $headers -Uri $PreemptUri -Body (ConvertTo-Json $authenticationsBody)
            $risk = $preemptRiskResponse.data.entities.nodes.riskScore
            $auths = $preemptAuthenticationsResponse.data.timeline.nodes
            $user | Add-Member -MemberType NoteProperty -Name "Cracked" -Value $wasCracked
            $user | Add-Member -MemberType NoteProperty -Name "PreemptRiskScore" -Value ($risk*10)
            $user | Add-Member -MemberType NoteProperty -Name "Last_5_Interactive_Auths" -Value ($auths.endpointEntity.primaryDisplayName -join "`n")
            if(!($i % 500)){
                Write-Progress -Activity "Enriching user information..." -Status "Scanned $i of $($AgedAccounts.count)" -PercentComplete (($i / $AgedAccounts.count) * 100)
            }
            $i++
        }
    }
    End{
        WriteSuccess -InputObject "Processing complete : Cracked users and Preempt enrichment"
        if($null -ne $OutputCsv -and $OutputCsv.Length -gt 1){
            Write-Information -MessageData "Outputting to $OutputCsv" -InformationAction Continue 
            foreach($user in $AgedAccounts){
                Export-Csv -Path $OutputCsv -InputObject $user -NoTypeInformation -Append
            }
        }
        else{
            return $AgedAccounts
        }
    }
}

function Invoke-Rc4Checks {
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [string]$RubeusPath,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutputDirectory,

        [Parameter(Mandatory=$false,Position=3)]
        [string]$OutputCsv = "rubeus_output.csv",

        [Parameter(Mandatory=$false,Position=4)]
        [array]$AccountsToEnrich=$global:RiskyAccounts
    )
    Begin{
        $trusts = Get-AllADDomains
        if(!$OutputCsv.EndsWith(".csv")){
            Write-Warning "Must specify a filename ending in csv, using default"
            $OutputCsv = "rubeus_output.csv"
        }
    }
    Process{
        #initial run
        foreach($trust in $trusts){
            Write-Information "Running rubeus for $trust" -InformationAction Continue
            $outputFile = "$OutputDirectory\$trust.txt"
            $files += $outputFile
            &$rubeusPath @("kerberoast","/rc4opsec","/domain:$trust") | Out-File -FilePath $outputFile -Append
        }
        
        #error checks
        Write-Verbose "Checking to ensure runs completed successfully"
        foreach($file in $files){
            #If the file has errors, probably didn't return any results
            #rerun for all users individually
            if(Get-Content $file | Select-String -Pattern "\[!\]\sUnhandled\sRubeus\sexception:"){
                $domain = $file.split("\")[-1]
                Write-Warning -Message "$domain didn't process successfully. Iterating over users and rerunning"
                Remove-Item -Path $file
                $users = (get-aduser -filter * -server $domain | Select-Object SamAccountName).SamAccountName
                foreach($user in $users){
                    # using the /rc4opsec flag will only grab those with rc4 as default; others may support it still
                    &$rubeusPath @("kerberoast","/domain:$domain","/user:$user") | Out-File -FilePath $file -Append
                }
            }
        }

        #parse the files
        Write-Information "Parsing Rubeus results for rc4 enabled accounts" -InformationAction Continue
        ConvertFrom-RubeusRawFiles -OutputDirectory $outputDirectory -OutputCsv $OutputCsv

        #ingest the accounts that had rc4 enabled
        $kerberoastedAccounts = Import-Csv "$outputDirectory\rubeus_output.csv"
        $rc4Accounts = $kerberoastedAccounts | Where-Object {$_.encryption -like '*RC4_HMAC*'}

        $i = 0
        foreach($user in $AccountsToEnrich){
            $rc4 = $false
            if ($rc4Accounts | Where-Object {$_.domain.tolower() -eq $user.Domain.tolower() -and $_.samaccountname -eq $user.SamAccountName}){
                $rc4 = $true
            }
            $user | Add-Member -MemberType NoteProperty -Name "Rc4 Supported" -Value $rc4
            if(!($i % 100)){
                Write-Progress -Activity "Flagging RC4 enabled accounts..." -Status "Completed $i of $($AccountsToEnrich.count)" -PercentComplete (($i / $AccountsToEnrich.count) * 100)
            }
            $i++
        }
    }
    End{
        WriteSuccess -InputObject "Processing complete : Rubeus RC4 checks"
        return $AccountsToEnrich
    }
}

function Invoke-SharpHound {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SharphoundPath,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutputDirectory
    )
    Begin{
        $domains = Get-AllADDomains
    }
    Process{
        foreach($domain in $domains){
            Write-Information "Running sharphound for $domain." -InformationAction Continue
            &$SharphoundPath @("-c All", "--outputdirectory `"$OutputDirectory\$domain`"", "-d $domain")
            Write-Information "Complete. Output written to $OutputDirectory\$domain" -InformationAction Continue
        }
    }
    End{
        WriteSuccess -InputObject "Processing complete : SharpHound"
    }
}

function Update-BloodhoundOwnedUsers {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CrackedAccounts,

        [Parameter(Mandatory=$false,Position=2)]
        [PSCredential]$neo4jCredential,

        [Parameter(Mandatory=$false,Position=3)]
        [string]$neo4jUrl="http://localhost:7474/db/data/transaction/commit"
    )
    Begin{
        if($null -eq $neo4jCredential){
            $neo4jCredential = Get-Credential -Message "Please enter your neo4j credentials"
        }
        $neo4jPassword = (New-Object System.Management.Automation.PSCredential -ArgumentList $neo4jCredential.UserName,$neo4jCredential.Password).GetNetworkCredential().Password
        $basicCred = ConvertTo-B64String -InputString "$($neo4jCredential.UserName):$neo4jPassword"
        $headers = @{
            "Accept"="application/json; charset=UTF-8";
            "Content-Type"="application/json";
            "Authorization"="Basic $basicCred"
        }
        $failedAccounts = @()
    }
    Process{
        foreach($account in $CrackedAccounts){
            $user = ($account.SamAccountName.toUpper() + "@" + $account.Domain.toUpper())
            $query = "MATCH (n) WHERE n.name=`"$user`" SET n.owned=true"
            $body = Convertto-Json @{"statments"=@(@{"statment"=$query})}
            try{
                Invoke-RestMethod -Method Post -Uri $neo4jUrl -Headers $headers -Body $body | Out-Null
                $success = $true
            }
            catch{
                $success = $false
                $failedAccounts += $user
            }
            Write-Verbose "User:{0,-50} Status:{1}" -f $user, $success
            if(!($i % 250)){
                Write-Progress -Activity "Marking owned users in BloodHound DB..." -Status "Marked $$i of $($CrackedAccounts.count)" -PercentComplete (($i / $CrackedAccounts.count) * 100)
            }
            $i++
        }
    }
    End{
        if($failedAccounts.length -gt 0){
            Write-Warning -Message ("The following failed to update:`n{0}" -f ($failedAccounts -join "`n"))
        }
        WriteSuccess -InputObject "Processing complete : BloodHound Owned Users"
    }
}

function Get-AllADDomains {
    param()   
    Begin{}
    Process{
        Write-Verbose "Getting all domains in current forest and established trusts"
        $allTrusts = @()
        foreach($forest in get-adforest){
            $allTrusts += (get-adtrust -filter * -server $forest).name
        }
        $trusts += $allTrusts
        foreach($t in $allTrusts){
            try{$trusts += (get-addomain $t).ChildDomains}
            catch{}
        }
    }
    End{
        return $trusts
    }
}

function ConvertFrom-B64String {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$EncodedString
    )
    begin{}
    process{
        $decodedString = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($encodedString))
    }
    end{
        return $decodedString
    }
}

function ConvertTo-B64String {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$InputString
    )
    begin{}
    process{
        $encodedString = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($inputString))
    }
    end{
        return $encodedString
    }
}

function WriteSuccess {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$InputObject
    )
    Begin{
        $StartingColor = $host.UI.RawUI.ForegroundColor
        $host.UI.RawUI.ForegroundColor = "DarkGreen"
    }
    Process{
        Write-Information -MessageData $InputObject -InformationAction Continue
    }
    End{
        $host.UI.RawUI.ForegroundColor = $StartingColor
    }
}

function ConvertFrom-RubeusRawFiles {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$OutputDirectory,

        [Parameter(Mandatory=$false,Position=2)]
        [string]$OutputCsv = "rubeus_output.csv"
    )
    Begin{}
    Process{
        $rubeusFiles = Get-ChildItem $OutputDirectory -File -Filter *.txt
        $ParserRegex = "\[\*\]\sSamAccountName\s*:\s*(\S+?)[\r\n\s].+?\[\*\]\sSupported\sETypes\s+:\s+([\s\S]+?)[\r\n]"
        #passing this will have the "." operator include newlines for regexs
        $SingleLineOption = 16
        foreach($file in $rubeusFiles){
            Write-Verbose "Reading $($file.Name)"
            $domain = $file.Name.substring(0,$file.Name.Length -4)
            # if you don't specify -Raw, it will return an array of string objects using new line as the delimiter
            # this would significantly complicate the regex
            $body = Get-Content $file.FullName -Raw
            $results = [regex]::Matches($body,$ParserRegex,$SingleLineOption)
            Write-Verbose "Found $($results.Length) results"
            foreach($result in $results){
                try{
                    $properties = [ordered]@{"domain"=$domain;"samaccountname"=$result.groups[1].Value;"encryption"=$result.groups[2].Value}
                    Export-Csv -InputObject (New-Object -Type psobject -Property $properties) -Path "$OutputDirectory`\$OutputCsv" -NoTypeInformation -Append
                }
                catch{
                    continue
                }
            }
        }
    }
    End{}
}

function Invoke-AuditPostProcessing {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$AuditResultsPath,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutputDirectory,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$RubeusPath,

        [Parameter(Mandatory=$true,Position=4)]
        [string]$SharphoundPath,

        [Parameter(Mandatory=$false,Position=5)]
        [bool]$PreemptEnrichment = $false,

        [Parameter(Mandatory=$false,Position=6)]
        [int]$AgeInYears=0
    )
    Begin{
        $CrackedAccounts = Import-Csv $AuditResults
        if($PreemptEnrichment){
            $ApiKey = Read-Host -Prompt "Enter Preempt API key" -AsSecureString
        }
        $neo4jCredential = Get-Credential -Message "Please enter your neo4j credentials"
    }
    Process{
        #query all domains in the forest for accounts older than $AgeInYears for risk related AD attributes
        #Appends to global array
        $Global:RiskyAccounts = Get-OldPwdAccounts -Years $AgeInYears -AllTrusts | Out-Null
        
        #correlate accounts with those that were cracked from the audit and supplement with Preempt information
        #Appends to global array
        if($PreemptEnrichment){
            Invoke-PreemptEnrichment -AgedAccounts $Global:RiskyAccounts -CrackedAccounts $CrackedAccounts -ApiKey $ApiKey | Out-Null
        }
        
        #attempt to kerberoast all accounts in each domain in the forest allowing us to see which accept rc4 encryption 
        #and parse results. Appends to global array
        #assumes rubeus.exe is in C:\Development\
        Invoke-Rc4Checks -RubeusPath $RubeusPath -OutputDirectory $OutputDirectory | Out-Null
        
        #run sharphound against each domain in the forest collecting all attributes
        #assumes sharphoud.exe is in C:\Development\BloodHound\Ingestors
        Invoke-SharpHound -SharphoundPath $SharphoundPath -OutputDirectory $OutputDirectory 
        
        #figure out how to import the zip files to bloodhound programmatically, for the time being, just wait for confirmation to continue
        $UpdateOwnedUsers = Read-Host -Prompt "Manually import the files now by starting BloodHound and dragging the zip files to the UI.`
        `nOnce this is complete, you can update the database to make users as 'owned' if their password was cracked.`
        `nWould you like to update the BloodHound DB with owned users? [y/n]:"
        
        #update bloodhound marking cracked accounts as owned
        #assumes default bloodhound isntance
        if($UpdateOwnedUsers -eq "y"){
            Update-BloodhoundOwnedUsers -CrackedAccounts $CrackedAccounts -neo4jCredential $neo4jCredential 
        }
        else{
            Write-Information "Skipping owned user update"
        }
    }
    End{
        WriteSuccess -InputObject "Processing complete : Audit Post Processing"
        return $global:RiskyAccounts
    }
}