<#
#####################################################################################
# Renamed from initial school project name of 'Get-ForensicData' to 'Invoke-ForensicCollection' for more appropriate PowerShell verb usage.
https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.2
FUNCTIONS
*** hash as you go, hash should be the renamed files, in a list for each function, and added to over-all data structure 
*** user output for feedback while it runs!
#>
########################
# Test 0
function Get-MachineVariables{
    $CaseName = Read-Host -Prompt "Please enter a name for this case"
    $CollectorName = Read-Host -Prompt "Please enter the name of the forensic collector (you)"
    $ComputerName = $env:COMPUTERNAME
    $Algorithm = 'MD5'
    $TargetVolume = @()

    $vols = Get-Volume
    $vols | ForEach-Object {
        if ( $_.DriveLetter -ne $null) {
            if($_.FileSystemLabel -eq 'resultstore'){
                $StorageVolume = $_.DriveLetter + ':'
            }
            elseif ($_.FileSystemLabel -eq 'configstore') {
                $ConfigVolume = $_.DriveLetter + ':'

            }
            elseif ($_.FileSystemLabel -eq 'scriptstore') {
                $ScriptVolume = $_.DriveLetter + ':'
            }
            else {
                # Add volume to list to be imaged, this accounts for multiple volumes
                $AddDrive = $_.DriveLetter + ':'
                $TargetVolume += $AddDrive
            }}}

    #$ScriptPath = Split-Path $MyInvocation.MyCommand.Path
    #$ScriptFile = $MyInvocation.MyCommand.Path
    #$ScriptPath = Split-Path -Path $ScriptFile

    # Create directory tree
    $RamCaptureDir = "$StorageVolume\$CaseName\$ComputerName\Capture\RAM"
    $DiskCaptureDir = "$StorageVolume\$CaseName\$ComputerName\Capture\DISK"
    $LiveResultsDir = "$StorageVolume\$CaseName\$ComputerName\Results\LIVE"
    $MemdumpResultsDir = "$StorageVolume\$CaseName\$ComputerName\Results\MEMDUMP"

    New-Item -Path  $RamCaptureDir -ItemType Directory
    New-Item -Path  $DiskCaptureDir -ItemType Directory
    New-Item -Path  $LiveResultsDir -ItemType Directory
    New-Item -Path  $MemdumpResultsDir -ItemType Directory

    #return data with environmentals, ordered is only used so that thesaved output is consistent, not for any other reason
    $MachineVariables =  [PSCustomObject]@{
        TargetVolume = $TargetVolume; 
        StorageVolume = $StorageVolume; 
        ConfigVolume = $ConfigVolume; 
        ScriptVolume = $ScriptVolume;
        #ScriptPath = $ScriptPath; 
        ComputerName = $ComputerName; 
        CollectorName = $CollectorName; 
        CaseName = $CaseName
        RamCaptureDir = $RamCaptureDir;
        DiskCaptureDir = $DiskCaptureDir;
        LiveResultsDir = $LiveResultsDir;
        MemdumpResultsDir = $MemdumpResultsDir;
        Algorithm = $Algorithm
    }
    return $MachineVariables
}

### --- CODE Test 1 (RAM) ############################################################
function Invoke-VolatileCapture{
    param ($ScriptDrive, $VolatileCaptureDestination, $Alg)

    $MemdumpStart = Get-Date 

    $MemFilePath = "$VolatileCaptureDestination\memdump.mem"
    
    $CurrentDetails = [PSCustomObject]@{
        Type = "RAM DUMP"
        Priority = 1
        StartTime = $MemdumpStart
        FilePath = $MemFilePath
        Alg = $Alg
    }

    Write-Start -CurrentDetails $CurrentDetails
    
    Invoke-Expression "$ScriptDrive\CollectionTools\winpmem\winpmem_mini_x64_rc2.exe $MemFilePath | Out-Null"

    $RamResult = Get-NewFileDetails -CurrentDetails $CurrentDetails

    Write-Stop -CurrentDetails $CurrentDetails

    return $RamResult
}

### --- CODE Test 2 (LIVE and MEMDUMP analysis) ######################################
function Get-AnalysisQueries{
    param($ScriptDrive)
    $JsonPath = $ScriptDrive
    $JsonFile = "ForensicDataCommands.json"
    $JsonContent = Get-Content -Path "$JsonPath\$JsonFile" | ConvertFrom-Json
    return $JsonContent
}
function Invoke-LiveAnalysis{
    param ($Command, $FileName, $ResultPath, $Alg)
    $Start = Get-Date

    $CurrentDetails = [PSCustomObject]@{
        Type = "LIVE ANALYSIS"
        Priority = 2
        StartTime = $Start
        FilePath = "$ResultPath\$FileName" 
        Alg = $Alg
    }

    Write-Start -CurrentDetails $CurrentDetails

    #Invoke-Expression "$Command -OutFile $ResultPath\$Filename | Out-Null"
    WriteHost "Attempting: $Command -OutFile $ResultPath\$Filename"
    Invoke-Expression "$Command -OutFile $ResultPath\$Filename"

    $LiveResult = Get-NewFileDetails -CurrentDetails $CurrentDetails

    Write-Stop -CurrentDetails $CurrentDetails

    return $LiveResult  
}

function Invoke-MemdumpAnalysis{
    param ($Command, $FileName, $ResultPath, $Alg)
    # volatility queries, **OPTIONAL**

    $Start = Get-Date

    $CurrentDetails = [PSCustomObject]@{
        Type = "STATIC ANALYSIS"
        Priority = 2
        StartTime = $Start
        FilePath = "$ResultPath\$FileName" 
        Alg = $Alg
    }

    Write-Start -CurrentDetails $CurrentDetails
    WriteHost "Attempting: $Command -OutFile $ResultPath\$Filename"
    #Invoke-Expression "$Command -OutFile $ResultPath\$Filename"

    #$StaticResult = Get-NewFileDetails -CurrentDetails $CurrentDetails

    Write-Stop -CurrentDetails $CurrentDetails

    #return $StaticResult
    return $CurrentDetails

}

### --- CODE Test 3 (DISK IMAGE) #####################################################
<#
function Get-ForensicDiskImage{
    param ($SomeArg, $SomeOtherArg)
    #FTK Imager CLI
    FTK Imager
	a. ftkimager.exe \\.\PHYSICALDRIVE%1 %2:\Training\Collection\<image name> —e01 —frag 2G —compress 6 —case-number TBD —evidence-number TBD —description TBD —examiner TBD   

}

function Invoke-ForensicDiskImage{
    param ($SomeArg, $SomeOtherArg)
    #target/source drive as arg
    $DestinationVolumeLabel = Get-StorageVolumeLabel

    # ^^^^^ fix that
    Get-ForensicDiskImage
        Call FTK Imager CLI with params from earlier (nested params)
}
#>
### --- CODE Test 4 (BIOS) ############################################################

function Get-BiosSettings{
    $Bios = Get-CimInstance -ClassName Win32_BIOS
    $Manuf = $Bios.Manufacturer
}


function Test-BiosChange{
    param ($ConfigVolume)
    # This is the non-results partition to store the configs for BIOS
    # should probably store this in the executive overview as well!
    <#
    query 
    backup (trivial to skip)
    edit to secure boot 
    query again 
    restore (trivial to skip)
    edit to remove secure boot 
    query again 

        3 times means make query a function!
    
    #>    

    Checkpoint-Bios #backup settings
        Get-Bios
    Edit-Bios
    Restore-Bios
}


###----------------------------------------------------------------------------------#####
<#
#for Lenovo
Get-WmiObject -class Lenovo_BiosSetting -namespace root\wmi
Get-WmiObject -class Lenovo_BiosSetting -namespace root\wmi select-object currentsetting 

Function Get_Lenovo_BIOS_Settings
{
 $Script:Get_BIOS_Settings = Get-WmiObject -class Lenovo_BiosSetting -namespace root\wmi  | select-object currentsetting | Where-Object {$_.CurrentSetting -ne ""} |
 select-object @{label = "Setting"; expression = {$_.currentsetting.split(",")[0]}} , 
 @{label = "Value"; expression = {$_.currentsetting.split(",*;[")[1]}} 
 $Get_BIOS_Settings
}

#check bios pw
If($IsPasswordSet -eq 1)
 {
  write-host "Password is configured"
 }
Else
 {
  write-host "No BIOS password"
 }

#without bios pw
$bios = gwmi -class Lenovo_SetBiosSetting -namespace root\wmi 
$bios.SetBiosSetting("WakeOnLAN,Disable") 
$Save_BIOS = (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi)
$Save_BIOS.SaveBiosSettings()

#change with bios pw
$MyPassword = "P@$$w0rd"
$bios = gwmi -class Lenovo_SetBiosSetting -namespace root\wmi 
$bios.SetBiosSetting("WakeOnLAN,Disable,$MyPassword,ascii,us")
$Save_BIOS = (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi)
$Save_BIOS.SaveBiosSettings("$MyPassword,ascii,fr")

#change from csv
$CSV_File = "D:\BIOS_Checker\BIOS_Change.csv"
$Get_CSV_Content = import-csv $CSV_File
$BIOS = gwmi -class Lenovo_SetBiosSetting -namespace root\wmi 
ForEach($Settings in $Get_CSV_Content)
 {
  $MySetting = $Settings.Setting
  $NewValue = $Settings.Value  
  $BIOS.SetBiosSetting("$MySetting,$NewValue") | out-null
 } 
$Save_BIOS = (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi)
$Save_BIOS.SaveBiosSettings()

#check settings
$Execute_Change_Action = $BIOS.SetBiosSetting("$MySetting,$NewValue")  
$Change_Return_Code = $Execute_Change_Action.return
If(($Change_Return_Code) -eq "Success")        
 {
  write-host "OK ==> New value for $MySetting is $NewValue"
 }
Else
 {
  write-host "KO ==> Can not change setting $MySetting (Return code $Change_Return_Code)" -Foreground Yellow
 } 
$Save_BIOS = (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi)        
$Save_BIOS.SaveBiosSettings()  
#>
###----------------------------------------------------------------------------------#####

function Invoke-ChangeBios{

}

function Restore-BiosSettings{
    param ($SomeArg, $SomeOtherArg)

}

function Edit-BiosSettings{
    param ($SomeArg, $SomeOtherArg)

}

### --- CODE Test 5 (EXEC SUMM) #######################################################
function Invoke-ExecutiveSummary{
    param ($CaptureDetails, $Results)

    $CaptureDetails | Format-Table
    $Results | Format-Table
}

### --- CODE Global Functs ###########################################################
function Get-DateTimeString{
    return (Get-Date -Format "yyyyMMdd").ToString(), (Get-Date -Format "HH:mm").ToString()
}

function Write-Start{
    param($CurrentDetails)
    $StartProc = $CurrentDetails.Type
    $OutFile = $CurrentDetails.FilePath
    Write-Host "Starting process $StartProc to Out-File $OutFile"
}

function Write-Stop{
    param($CurrentDetails)
    $StopProc = $CurrentDetails.Type
    $OutFile = $CurrentDetails.FilePath
    Write-Host "Completed process $StopProc to Out-File $OutFile"
}
<#
    Pass in:
        $CurrentDetails = [PSCustomObject]@{
            Type = "Basic File"
            Priority = 6 # INT variable @ priority of capture (for sort)
            StartTime = $StartTime
            FilePath = $F.FullName
            Alg = $Alg
        }
    $Results += (Get-FileData -CurrentDetails $CurrentDetails)  
#>

function Get-NewFileDetails{        #Takes PSCObj, hashes, size of file, rename with date, returns PSCObj
    param ($CurrentDetails)
    # Unpack, declare locals, make changes
    $StartTime = $CurrentDetails.StartTime
    $Alg = $CurrentDetails.Alg
    $FullName = $CurrentDetails.FilePath 
    $FileName = Split-Path -Path $FullName -Leaf -Resolve
    $FilePath = Split-Path -Path $FullName

    if ($CurrentDetails.Priority -ne 1 -And $CurrentDetails.Priority -ne 3){
        $ContentCount = ((Get-Content -Path $FullName).Length -1)
    }
    else {
        $ContentCount = 1
    }

    $Filesize = (Get-ChildItem $FullName).Length
    $Date, $Time = Get-DateTimeString
    $Hash = (Get-FileHash -Algorithm $Alg $FullName).Hash
    #$NewName = "$Date-$Hash-$FileName"
    $NewName = "$Date-$FileName"
    $NewPath = "$FilePath\$NewName"
    Rename-Item -Path $FullName -NewName $NewPath
    $StopTime = Get-Date 
    $Duration = $StopTime - $StartTime
    # $Duration.TotalSeconds

    # Add details to new object, return
    $FileDetails = [PSCustomObject]@{
        Priority = $CurrentDetails.Priority
        Type = $CurrentDetails.Type 
        InitialFileName = $FileName 
        ContentCount = $ContentCount
        FileSize = $Filesize
        HashType = $Alg 
        Hash = $Hash
        StartTime = $StartTime
        StopTime = $StopTime
        Duration = $Duration
        NewFileName = $NewName
    }
    return $FileDetails
}

### --- CODE (MAIN) ###################################################################
function Invoke-ForensicCapture{

    $GlobalStart = Get-Date
    $Results = @()
    Write-Host "Initiating Script ... getting environmentals ... "

    # Test 0, getting the environmental variables
    $MachineVariables = Get-MachineVariables
    
    $TargetVolume = $MachineVariables.TargetVolume 
    $StorageVolume = $MachineVariables.StorageVolume; 
    $ConfigVolume = $MachineVariables.ConfigVolume; 

    $DiskCaptureDir = $MachineVariables.DiskCaptureDir;
    $LiveResultsDir = $MachineVariables.LiveResultsDir;
    $MemdumpResultsDir = $MachineVariables.MemdumpResultsDir;
    $Alg = $MachineVariables.Algorithm

    ### --- RUN Test 1 (RAM) ############################################################
    #$RamResults = Invoke-VolatileCapture -ScriptDrive $MachineVariables.ScriptVolume -VolatileCaptureDestination $MachineVariables.RamCaptureDir -Alg $Alg
    #$Results += $RamResults

    ### --- RUN Test 2 (LIVE and MEMDUMP analysis) ######################################
    $Commands = Get-AnalysisQueries -ScriptDrive $MachineVariables.ScriptVolume
    $CmdPath = $MachineVariables.ScriptVolume

    #2.1
    $ScriptToolFolder = $Commands.LiveDir 
    $QueryType = "Live"
    
    foreach ($Cmd in $Commands.$QueryType){
        $SubFolder = $Cmd.SubFolder 
        $Exec = $Cmd.Command 
        $ExecPath = "$CmdPath\$ScriptToolFolder\$SubFolder\$Exec"
        $OutFile = $Cmd.OutFile
        Write-Host "Troubleshoot: ExecPath:$ExecPath; OutFile:$OutFile; ResultPath:$LiveResultsDir;"
        $LiveResult = Invoke-LiveAnalysis -Command $ExecPath -ResultPath $LiveResultsDir -FileName $OutFile -Alg $Alg 
        $Results += $LiveResult
    }

    #2.2
    $ScriptToolFolder = $Commands.VolatilityDir
    $QueryType = "Volatility"
    $Exec = "volatility-2.6_win64_standalone.exe"
    $RamProfile = "Win7SP1x64"
    <#  imageinfo -> Win7SP1x64, WinXPSP2x86  #>
    <# volatility-2.5.standalone.exe -f <image file path> --profile=<memory profile> <plug-in> #>

    foreach ($Cmd in $Commands.$QueryType){
        $SubFolder = $Cmd.SubFolder 
        $Module = $Cmd.Module 
        $ExecPath = "$CmdPath\$ScriptToolFolder\$SubFolder\$Exec -f $memdumpFile --profile=$RamProfile $Module"
        $OutFile = $Cmd.OutFile
        
        $LiveResult = Invoke-LiveAnalysis -Command $ExecPath -ResultPath $MemdumpResultsDir -FileName $OutFile -Alg $Alg 
        #$Results += $LiveResult
    }



    #Invoke-MemdumpAnalysis
    #volatility analysis

    ### --- RUN Test 3 (DISK IMAGE) #####################################################
    #Invoke-ForensicDiskImage
    <#target/source drive as arg
    foreach ($Target in $TargetVolume){

    }
    
    $DiskCaptureDir

    Get-StorageVolumeLabel
    Get-ForensicDiskImage
        Iterate through all volumes!
        Call FTK Imager CLI with params from earlier (nested params)
    #>

    ### --- RUN Test 4 (BIOS) ############################################################
    #Test-BiosChange -ConfigVolume $MachineVariables.ConfigVolume

    ### --- RUN Test 5 (EXEC SUMM) #######################################################
    $GlobalStop = Get-Date
    $GlobalDuration = $GlobalStop - $GlobalStart

    $CaptureDetails = [PSCustomObject]@{
        Event = "FullCapture"
        CollectorName = $MachineVariables.CollectorName
        CaseName = $MachineVariables.CaseName
        ComputerName = $MachineVariables.ComputerName 
        HashAlg = $MachineVariables.Alg
        CaptureStart = $GlobalStart
        CaptureStop = $GlobalStop
        CaptureDuration = $GlobalDuration
    }
    Invoke-ExecutiveSummary -CaptureDetails $CaptureDetails -Results $Results
    # final actions, gather results and save custom data as both text, and JSON object
    # Output times / hashes / filecounts to host
}

####################################################################################
### --- RUN STARTS HERE ############################################################
Invoke-ForensicCapture
<# ------------------------------------------------------------------------------ #>
