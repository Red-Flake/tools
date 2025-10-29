
function Enable-Privilege {
    <#
        .SYNOPSIS
            Enables or disables security privileges on a target process.

        .DESCRIPTION
            Enables or disables security privileges on a target process.
            Multiple privileges can be set at once, separated by a comma.

        .PARAMETER Privilege
            Privileges to enable or disable on a target process, e.g. SeBackupPrivilege, SeRestorePrivilege.
            Alias: -Priv

        .PARAMETER Disable
            Disable privileges.

        .PARAMETER ProcessID
            Target process ID. Special values: -1 (current) and -2 (parent). Default: -1 (current process)
            Alias: -PID
 
        .INPUTS
            System.String[] Privilege
            System.Int32 PID
            
        .OUTPUTS
            System.Boolean
            
        .NOTES
            Version : 1.0.0

            Valid privilege names
            =====================
            'SeAssignPrimaryTokenPrivilege', 'SeAuditPrivilege', 'SeBackupPrivilege',
            'SeBatchLogonRight', 'SeChangeNotifyPrivilege', 'SeCreateGlobalPrivilege',
            'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeCreateSymbolicLinkPrivilege',
            'SeCreateTokenPrivilege', 'SeDebugPrivilege', 'SeDelegateSessionUserImpersonatePrivilege',
            'SeDenyBatchLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyNetworkLogonRight',
            'SeDenyRemoteInteractiveLogonRight', 'SeDenyServiceLogonRight', 'SeEnableDelegationPrivilege',
            'SeImpersonatePrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeIncreaseQuotaPrivilege',
            'SeIncreaseWorkingSetPrivilege', 'SeInteractiveLogonRight', 'SeLoadDriverPrivilege',
            'SeLockMemoryPrivilege', 'SeMachineAccountPrivilege', 'SeManageVolumePrivilege',
            'SeNetworkLogonRight', 'SeProfileSingleProcessPrivilege', 'SeRelabelPrivilege',
            'SeRemoteInteractiveLogonRight', 'SeRemoteShutdownPrivilege', 'SeRestorePrivilege',
            'SeSecurityPrivilege', 'SeServiceLogonRight', 'SeShutdownPrivilege',
            'SeSyncAgentPrivilege', 'SeSystemEnvironmentPrivilege', 'SeSystemProfilePrivilege',
            'SeSystemtimePrivilege', 'SeTakeOwnershipPrivilege', 'SeTcbPrivilege',
            'SeTimeZonePrivilege', 'SeTrustedCredManAccessPrivilege', 'SeUndockPrivilege',
            'SeUnsolicitedInputPrivilege'

        .LINK
            More info: https://docs.microsoft.com/windows/win32/secauthz/privilege-constants
    #>
    [cmdletbinding(
        ConfirmImpact = 'low',
        SupportsShouldProcess = $true
        #PositionalBinding = $false  ## Requires PS >=3.0
    )]
    [OutputType('System.Boolean')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias("Priv")]
        [ValidateSet(
            'SeAssignPrimaryTokenPrivilege',
            'SeAuditPrivilege',
            'SeBackupPrivilege',
            'SeBatchLogonRight',
            'SeChangeNotifyPrivilege',
            'SeCreateGlobalPrivilege',
            'SeCreatePagefilePrivilege',
            'SeCreatePermanentPrivilege',
            'SeCreateSymbolicLinkPrivilege',
            'SeCreateTokenPrivilege',
            'SeDebugPrivilege',
            'SeDelegateSessionUserImpersonatePrivilege',
            'SeDenyBatchLogonRight',
            'SeDenyInteractiveLogonRight',
            'SeDenyNetworkLogonRight',
            'SeDenyRemoteInteractiveLogonRight',
            'SeDenyServiceLogonRight',
            'SeEnableDelegationPrivilege',
            'SeImpersonatePrivilege',
            'SeIncreaseBasePriorityPrivilege',
            'SeIncreaseQuotaPrivilege',
            'SeIncreaseWorkingSetPrivilege',
            'SeInteractiveLogonRight',
            'SeLoadDriverPrivilege',
            'SeLockMemoryPrivilege',
            'SeMachineAccountPrivilege',
            'SeManageVolumePrivilege',
            'SeNetworkLogonRight',
            'SeProfileSingleProcessPrivilege',
            'SeRelabelPrivilege',
            'SeRemoteInteractiveLogonRight',
            'SeRemoteShutdownPrivilege',
            'SeRestorePrivilege',
            'SeSecurityPrivilege',
            'SeServiceLogonRight',
            'SeShutdownPrivilege',
            'SeSyncAgentPrivilege',
            'SeSystemEnvironmentPrivilege',
            'SeSystemProfilePrivilege',
            'SeSystemtimePrivilege',
            'SeTakeOwnershipPrivilege',
            'SeTcbPrivilege',
            'SeTimeZonePrivilege',
            'SeTrustedCredManAccessPrivilege',
            'SeUndockPrivilege',
            'SeUnsolicitedInputPrivilege'
        )]
        [string[]]
        $Privilege,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias("PID")]
        [int]
        $ProcessID = -1,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        $Disable,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        $Force
    )

    begin {
        $return = $false
        $go = $false
        $signature = '[StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES {
            public long Luid;
            public int Attributes;
        }

        public const int MAX_PRIVILEGES = 46;
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES {
            public int Count;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MAX_PRIVILEGES)]
            public LUID_AND_ATTRIBUTES [] Privileges;
        }
        
        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, out PROCESS_BASIC_INFORMATION pbi, int len, out int pSize);

        [DllImport("advapi32.dll")]
        public static extern bool OpenProcessToken(IntPtr hProcess, int dwAccess, out IntPtr hToken);
 
        [DllImport("advapi32.dll")]
        public static extern bool LookupPrivilegeValue(string host, string name, out long pLuid);
        
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hHandle);
        
        [DllImport("advapi32.dll", EntryPoint="AdjustTokenPrivileges", SetLastError=true)]
        private static extern bool _AdjustTokenPrivileges(IntPtr hToken, bool bDisableAllPrivileges, ref TOKEN_PRIVILEGES pNewState, int len, IntPtr pPrevState, out int pSize);
        
        public static bool AdjustTokenPrivileges(IntPtr hToken, bool bDisableAllPrivileges, ref TOKEN_PRIVILEGES pNewState, int len, IntPtr pPrevState, out int pSize)
        {
            return _AdjustTokenPrivileges(hToken, bDisableAllPrivileges, ref pNewState, len, pPrevState, out pSize) && System.Runtime.InteropServices.Marshal.GetLastWin32Error()==0;
        }'
        
        try {
            Add-Type -MemberDefinition $signature -Namespace AdjPriv -Name Privilege -ErrorAction Stop 
        }
        catch {
            $PSCmdlet.WriteError($_)
            return
        }
        $go = $true
    }

    process {
        if (!$go) {
            return
        }

        if ($Privilege.Count -gt ([AdjPriv.Privilege]::MAX_PRIVILEGES)) {
            Write-Warning "[Enable-Privilege] Input size larger than MAX_PRIVILEGES ($([AdjPriv.Privilege]::MAX_PRIVILEGES))"
            return
        }

        if ($ProcessID -eq -2) {
            $pbi = New-Object AdjPriv.Privilege+PROCESS_BASIC_INFORMATION
            $status = [int][AdjPriv.Privilege]::NtQueryInformationProcess(-1, 0, [ref]$pbi, [System.Runtime.InteropServices.Marshal]::SizeOf($pbi), [ref]$null)
            if ($status) {
                Write-Warning "[Enable-Privilege] NtQueryInformationProcess() FAIL ($status)"
                return
            }
            Write-Verbose "[Enable-Privilege] NtQueryInformationProcess() OK"
            $ProcessID = $pbi.InheritedFromUniqueProcessId
        } elseif (($ProcessID -eq 0) -or ($ProcessID -eq -1)) {
            $ProcessID = $PID
        }

        $Process = Get-Process -id $ProcessID
        if (!$Process) {
            return
        } elseif ($Process.ProcessName -eq "explorer" -and !$Force) {
            Write-Warning "[Enable-Privilege] Target process is $($Process.MainModule.ModuleName) (PID: $ProcessID), skipping."
            Write-Warning "[Enable-Privilege] Use -Force to skip this message and set privileges anyway."
            return
        }

        [IntPtr]$hProc = -1
        if ($ProcessID -ne $PID) {
            $hProc = $Process.Handle
        }

        $txt = $null
        $attr = 0
        if ($Disable) {
            $txt = "Disable"
        } else {
            $txt = "Enable"
            $attr = 2
        }

        $privnames = @()
        $privileges = New-Object AdjPriv.Privilege+LUID_AND_ATTRIBUTES[] ([AdjPriv.Privilege]::MAX_PRIVILEGES)
        $c = 0
        foreach ($priv in $Privilege) {
            [long]$privId = $null
            $ok = [bool][AdjPriv.Privilege]::LookupPrivilegeValue($null, $priv, [ref]$privId)
            if ($ok) {
                Write-Verbose "[Enable-Privilege] LookupPrivilegeValue() Found token ""$priv"" LUID $privId"
                $privileges[$c++] = New-Object AdjPriv.Privilege+LUID_AND_ATTRIBUTES -Property @{Luid = $privId; Attributes = $attr}
                $privnames += $priv
            } else {
                Write-Warning "[Enable-Privilege] LookupPrivilegeValue() Could not find token ""$priv"" LUID !"
                #return $false
            }
        }
        Write-Verbose "[Enable-Privilege] Total privileges: $c"

        If ($PSCmdlet.ShouldProcess("Process: $($Process.MainModule.ModuleName) (PID: $ProcessID)", "$txt Privileges: $($privnames -join ', ')")) {
            if ($c -gt 0) {
                $tokenPriv = New-Object AdjPriv.Privilege+TOKEN_PRIVILEGES
                $tokenPriv.Count = $c
                $tokenPriv.Privileges = $privileges
                $hToken = [IntPtr]::Zero
                $return = [bool][AdjPriv.Privilege]::OpenProcessToken($hProc, 40, [ref]$hToken)
                if ($return) {
                    Write-Verbose "[Enable-Privilege] OpenProcessToken() OK"
                    $return = [bool][AdjPriv.Privilege]::AdjustTokenPrivileges($hToken, $false, [ref]$tokenPriv, [System.Runtime.InteropServices.Marshal]::SizeOf($tokenPriv), [IntPtr]::Zero, [ref]$null)
                    $null = [bool][AdjPriv.Privilege]::CloseHandle($hToken)
                    if ($return) {
                        Write-Verbose "[Enable-Privilege] AdjustTokenPrivileges() OK"
                    } else {
                        Write-Warning "[Enable-Privilege] AdjustTokenPrivileges() FAIL"
                    }
                } else {
                    Write-Warning "[Enable-Privilege] OpenProcessToken() FAIL"
                }
            }
        }
    }

    end {
        $txt = $null
        if ($Disable) {
            $txt = "disable"
        } else {
            $txt = "enable"
        }

        if ($return) {
            Write-Host "[Enable-Privilege] $c privileges $txt`d successfully. (Target: $($Process.MainModule.ModuleName) PID: $ProcessID)"
        } else {
            Write-Warning "[Enable-Privilege] Could not $txt $c privileges! (Target: $($Process.MainModule.ModuleName) PID: $ProcessID)"
        }
        return [bool]$return
    }
}

# main

if ($MyInvocation.InvocationName -ne '.') {
    if (($args -contains '-help') -or ($args -contains '-?') -or (!($PSBoundParameters.ContainsKey('Privilege')) -and !($PSBoundParameters.ContainsKey('Priv')) -and ($args -notcontains '-Privilege') -and ($args -notcontains '-Priv'))) {
        Write-Output "`n *** Enable-Privilege.ps1 ***`n"
        Get-Help Enable-Privilege -detailed
    } else {
        $_args = $args | Where-Object { $_ -ne 'Enable-Privilege' }
        $null = Enable-Privilege @_args @PSBoundParameters
    }
}
