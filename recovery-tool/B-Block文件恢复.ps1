#Requires -Version 3.0
<#
.SYNOPSIS
    B-Block 文件夹紧急恢复工具（零依赖，无需管理员，不删除任何文件）

.DESCRIPTION
    用于「上锁/解锁流程中断」导致的文件夹消失：
      状态通常是——文件夹被设为 隐藏(HIDDEN/SYSTEM) + 被插入了一条 DENY 拒绝当前用户访问的 ACE，
      但 B-Block 的配置里已经没有记录（或记录为 unlocked），导致软件里看不到、门户 .lnk 也没了。

    本脚本只做三件事：
      1) 去掉隐藏/系统属性
      2) 删除针对当前用户的 DENY 拒绝规则
      3) 重新授予当前用户完全控制
    【绝对不会删除、移动、重命名任何文件或文件夹】

    默认 dry-run（只报告将要做什么）。真正执行请加 -Apply。

.EXAMPLE
    .\B-Block文件恢复.ps1                      # 交互菜单
    .\B-Block文件恢复.ps1 -Mode Scan           # 扫描本机被隐藏/被拒绝的文件夹
    .\B-Block文件恢复.ps1 -Mode Recover -Path "D:\xxx\账号密码" -Apply
#>
param(
    [ValidateSet('Menu', 'Scan', 'Recover')]
    [string]$Mode = 'Menu',
    [string]$Path = '',
    [string]$Root = '',
    [switch]$Apply
)

$ErrorActionPreference = 'Continue'
$LogFile = Join-Path $PSScriptRoot ("恢复日志_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:Changes = 0

function Write-Log {
    param([string]$Msg, [string]$Color = 'Gray')
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Get-MySid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Test-IsDenied {
    param([string]$P)
    try {
        $acl = Get-Acl -LiteralPath $P -ErrorAction Stop
        $sid = Get-MySid
        $deny = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid
        }
        return ($null -ne $deny)
    } catch {
        return $false
    }
}

function Show-AclDeny {
    param([string]$P)
    try {
        $acl = Get-Acl -LiteralPath $P -ErrorAction Stop
        $items = $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }
        if ($items) {
            foreach ($i in $items) { Write-Log ("      拒绝规则: {0}  {1}" -f $i.IdentityReference, $i.FileSystemRights) 'Yellow' }
        } else {
            Write-Log "      无拒绝规则" 'DarkGray'
        }
    } catch {
        Write-Log "      读取权限失败: $($_.Exception.Message)" 'DarkGray'
    }
}

function Repair-Folder {
    param([string]$P, [bool]$DoApply)

    if (-not (Test-Path -LiteralPath $P)) {
        Write-Log "  路径不存在，跳过: $P" 'Red'
        return
    }

    $item = Get-Item -LiteralPath $P -Force
    $attr = $item.Attributes
    $needUnhide = [bool]($attr -band [IO.FileAttributes]::Hidden) -or [bool]($attr -band [IO.FileAttributes]::System)

    Write-Log ("  当前属性: {0}" -f $attr) 'Cyan'
    Show-AclDeny -P $P

    $sid  = Get-MySid
    $user = "$env:USERDOMAIN\$env:USERNAME"

    # 顺序至关重要（实测）：DENY 生效时 attrib 会直接报「拒绝访问」，
    # 必须「先解 DENY 再清属性」，不能反过来。
    if ($DoApply) {
        & icacls "$P" /remove:d "*$sid" /T /C /Q 2>$null
        Write-Log "  [已执行] 移除针对本用户的拒绝规则 (icacls /remove:d)" 'Green'
        & icacls "$P" /grant:r "${user}:(OI)(CI)F" /T /C /Q 2>$null
        Write-Log "  [已执行] 重新授予完全控制 (icacls /grant:r)" 'Green'
        $script:Changes++
    } else {
        Write-Log "  [将执行] icacls `"$P`" /remove:d *$sid /T /C /Q" 'Yellow'
        Write-Log "  [将执行] icacls `"$P`" /grant:r ${user}:(OI)(CI)F /T /C /Q" 'Yellow'
    }

    if ($needUnhide) {
        if ($DoApply) {
            try {
                & attrib -h -s "$P" 2>$null
                Write-Log "  [已执行] 清除隐藏/系统属性" 'Green'
                $script:Changes++
            } catch { Write-Log "  [失败] 清除属性: $($_.Exception.Message)" 'Red' }
        } else {
            Write-Log "  [将执行] 清除隐藏/系统属性 (attrib -h -s)" 'Yellow'
        }
    } else {
        Write-Log "  无需清除属性" 'DarkGray'
    }

    if ($DoApply) {
        try {
            [void](Get-ChildItem -LiteralPath $P -Force -ErrorAction Stop)
            Write-Log "  验证：文件夹可正常访问 OK" 'Green'
        } catch {
            Write-Log "  仍无法访问，请以管理员身份重试（必要时先 takeown 夺取所有权）" 'Yellow'
        }
    }
}

function Find-Candidates {
    param([string[]]$Roots)

    $found = @()
    foreach ($r in $Roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        Write-Log "扫描: $r" 'Cyan'
        try {
            $dirs = Get-ChildItem -LiteralPath $r -Force -Recurse -Directory -ErrorAction SilentlyContinue
        } catch { continue }
        foreach ($d in $dirs) {
            $isHidden = [bool]($d.Attributes -band [IO.FileAttributes]::Hidden) -or [bool]($d.Attributes -band [IO.FileAttributes]::System)
            if ($isHidden -or (Test-IsDenied -P $d.FullName)) {
                $found += [PSCustomObject]@{
                    序号   = $found.Count + 1
                    路径   = $d.FullName
                    属性   = $d.Attributes
                    被拒绝 = (Test-IsDenied -P $d.FullName)
                }
            }
        }
    }
    return $found
}

# ------------------------------ 主流程 ------------------------------
Write-Log "=== B-Block 文件夹恢复工具 ===" 'White'
Write-Log ("当前用户: {0}\{1}   SID: {2}" -f $env:USERDOMAIN, $env:USERNAME, (Get-MySid)) 'White'
if ($Mode -ne 'Menu') {
    Write-Log ("模式: {0}   {1}" -f $Mode, $(if ($Apply) { '【实际执行】' } else { '【预演，不改动任何东西】' })) $(if ($Apply) { 'Green' } else { 'Yellow' })
}
Write-Log "日志文件: $LogFile" 'DarkGray'

if ($Mode -eq 'Menu') {
    Write-Host "`n请选择：" -ForegroundColor White
    Write-Host "  1) 扫描电脑，找出被隐藏/被拒绝访问的文件夹"
    Write-Host "  2) 恢复指定路径的文件夹"
    $c = Read-Host "输入 1 或 2"
    if ($c -eq '1') { $Mode = 'Scan' } else {
        $Mode = 'Recover'
        if (-not $Path) { $Path = Read-Host "请输入文件夹完整路径" }
    }
    if (-not $Apply) {
        $a = Read-Host "是否【实际执行】修复？输入 y 执行，其它键只预演不改动"
        if ($a -eq 'y' -or $a -eq 'Y') { $Apply = $true }
    }
}

if ($Mode -eq 'Scan') {
    if (-not $Root) {
        $roots = @(
            (Join-Path $env:USERPROFILE 'Desktop'),
            (Join-Path $env:USERPROFILE 'Documents'),
            (Join-Path $env:USERPROFILE 'Downloads'),
            (Join-Path $env:USERPROFILE 'Pictures')
        )
        $extra = Read-Host "还要扫描其他根目录吗？(直接回车跳过，或输入如 D:\)"
        if ($extra) { $roots += $extra }
    } else { $roots = @($Root) }

    $res = Find-Candidates -Roots $roots
    if ($res.Count -eq 0) {
        Write-Log "未发现可疑文件夹。" 'Green'
    } else {
        Write-Host "`n发现以下可疑文件夹：" -ForegroundColor Yellow
        $res | ForEach-Object {
            Write-Host ("  [{0}] {1}" -f $_.序号, $_.路径) -ForegroundColor White
            Write-Host ("      属性={0}  被拒绝={1}" -f $_.属性, $_.被拒绝) -ForegroundColor DarkGray
        }
        $sel = Read-Host "`n要恢复哪一个？输入序号（多个用逗号分隔，直接回车退出）"
        if ($sel) {
            foreach ($n in ($sel -split ',')) {
                $idx = [int]($n.Trim()) - 1
                if ($idx -ge 0 -and $idx -lt $res.Count) {
                    Write-Log "--- 处理: $($res[$idx].路径)" 'White'
                    Repair-Folder -P $res[$idx].路径 -DoApply $Apply
                }
            }
        }
    }
} elseif ($Mode -eq 'Recover') {
    if (-not $Path) { $Path = Read-Host "请输入文件夹完整路径" }
    Write-Log "--- 处理: $Path" 'White'
    Repair-Folder -P $Path -DoApply $Apply
}

Write-Log "=== 完成，共执行 $script:Changes 项修复 ===" 'White'
if (-not $Apply) {
    Write-Host "`n提示：以上是预演。确认无误后，重新运行并加上 -Apply 才会真正修复。" -ForegroundColor Yellow
    Write-Host "示例： .\B-Block文件恢复.ps1 -Mode Recover -Path `"D:\xxx\文件夹`" -Apply" -ForegroundColor Yellow
}
# 仅在真正的交互式控制台等待回车（自动化/管道调用时直接结束，避免卡住）
if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
    Write-Host "`n按回车键退出..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
