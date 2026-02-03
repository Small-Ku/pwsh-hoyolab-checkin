####################
# Utilities
####################

function New-WebSession {
	# From https://stackoverflow.com/questions/69519695
	param(
		[hashtable]$Cookies,
		[Uri]$For
	)

	$newSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()

	foreach ($entry in $Cookies.GetEnumerator()) {
		$cookie = [System.Net.Cookie]::new($entry.Name, $entry.Value)
		if ($For) {
			$newSession.Cookies.Add([uri]::new($For, '/'), $cookie)
		}
		else {
			$newSession.Cookies.Add($cookie)
		}
	}

	return $newSession
}

function Format-Text {
	# Temporary hack for Windows PowerShell that not handle REST requests with UTF-8
	param(
		[String]$Text
	)

	if ($null -eq $Text) { return "" }

	if ($PSVersionTable.PSVersion.Major -le 5) {
		$bytes = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetBytes($Text)
		return [System.Text.Encoding]::UTF8.GetString($bytes)
	}

	return $Text
}

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
		[String]$Level,
		[Parameter(Mandatory = $true)]
		[String]$Message
	)

	$color = switch ($Level) {
		'INFO' { 'Cyan' }
		'WARN' { 'Yellow' }
		'ERROR' { 'Red' }
		'DEBUG' { 'Gray' }
	}

	if ($Level -eq 'DEBUG' -and -not $global:debugging) { return }
	if ($null -ne $conf -and -not $conf.display.console) { return }

	Write-Host "[$Level] $Message" -ForegroundColor $color
}

####################
# Discord
####################

function Get-DiscordPing {
	param($PingConfig)
	if (-not $PingConfig) { return "" }

	$ping = ""
	if ($PingConfig.user) {
		$ping += "<@" + ($PingConfig.user -join "> <@") + ">"
	}
	if ($PingConfig.user -and $PingConfig.role) {
		$ping += " "
	}
	if ($PingConfig.role) {
		$ping += "<@&" + ($PingConfig.role -join "> <@&") + ">"
	}
	return $ping
}

function Initialize-DiscordEmbed {
	return @{
		'color'       = '16711680' # Default to Red (Error)
		'title'       = "ERROR"
		'description' = "Unknown error. Maybe invalid cookie."
		'fields'      = @()
	}
}

function Send-DiscordNotification {
	param(
		$Config,
		$Embeds,
		$NeedPing,
		$PingString
	)

	if (-not $Config.display.discord.webhook_url) { return }

	$discord_body = @{
		'content' = ''
		'embeds'  = $Embeds
	}
	if ($Config.display.discord.username) { $discord_body.username = $Config.display.discord.username }
	if ($Config.display.discord.avatar_url) { $discord_body.avatar_url = $Config.display.discord.avatar_url }

	$discord_body_json = $discord_body | ConvertTo-Json -Depth 10

	Write-Log -Level 'DEBUG' -Message "Discord message body:`n$discord_body_json"

	$reuse_id = $Config.display.discord.reuse_msg
	if ($reuse_id -and $reuse_id -match '^\d{18,}$') {
		$uri = "$($Config.display.discord.webhook_url)/messages/$reuse_id"
		$ret = Invoke-WebRequest -Method 'Patch' -Uri $uri -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
	}
	else {
		$uri = $Config.display.discord.webhook_url + '?wait=true'
		$ret = Invoke-RestMethod -Method 'Post' -Uri $uri -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
		if ($Config.display.discord.reuse_msg -eq 'true' -or $Config.display.discord.reuse_msg -eq $true) {
			$Config.display.discord.reuse_msg = $ret.id
			$Config | ConvertTo-Json -Depth 10 | Set-Content .\sign.json -Encoding 'UTF8'
		}
	}

	if ($NeedPing) {
		$ping_body = @{ 'content' = $PingString } | ConvertTo-Json
		Invoke-RestMethod -Method 'Post' -Uri $Config.display.discord.webhook_url -Body $ping_body -ContentType 'application/json;charset=UTF-8'
	}
}

####################
# HoYoLAB
####################

function Test-HoyolabCookie {
	param($CookieString)
	if ($CookieString -like "*ltoken_v2=*") {
		return (($CookieString -match 'ltoken_v2=v2_[^\s;]{114,}') -and ($CookieString -match 'ltmid_v2=[0-9a-zA-Z_]{13}') -and ($CookieString -match 'ltuid_v2=(\d+)'))
	}
	else {
		return (($CookieString -match 'ltoken=[0-9a-zA-Z]{40}') -and ($CookieString -match 'ltuid=(\d+)'))
	}
}

function Get-HoyolabAccountInfo {
	param($Cookies, $UserAgent, $Config)

	$session = New-WebSession -Cookies $Cookies -For 'https://api-account-os.hoyolab.com'
	$headers = @{
		'Accept'          = 'application/json, text/plain, */*'
		'Accept-Language' = 'en-US,en;q=0.9'
		'Origin'          = 'https://act.hoyolab.com'
		'Referer'         = 'https://act.hoyolab.com/'
		'Sec-Fetch-Site'  = 'same-site'
		'Sec-Fetch-Mode'  = 'cors'
		'Sec-Fetch-Dest'  = 'empty'
	}
	$uri = 'https://api-account-os.hoyolab.com/auth/api/getUserAccountInfoByLToken'
	$ret = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $UserAgent -WebSession $session

	Write-Log -Level 'DEBUG' -Message "Account info: $ret data: $($ret.data)"

	if ($ret.retcode -eq 0) {
		$display_name = ''
		if ($Config.display.account_info.name -and $ret.data.account_name) { $display_name = $ret.data.account_name }
		elseif ($Config.display.account_info.email -and $ret.data.email) { $display_name = $ret.data.email }
		elseif ($Config.display.account_info.id -and $ret.data.account_id) { $display_name = $ret.data.account_id }
		elseif ($Config.display.account_info.phone -and $ret.data.mobile) { $display_name = $ret.data.mobile }

		return @{ Success = $true; DisplayName = $display_name }
	}

	return @{ Success = $false; Message = $ret.message }
}

function Invoke-HoyolabCheckin {
	param($Cookie, $Config, $Embed)

	if (-not (Test-HoyolabCookie -CookieString $Cookie)) {
		Write-Log -Level 'ERROR' -Message "Invalid cookie format: $Cookie"
		return $null
	}

	$ltuid = $Matches.1
	$display_name = $ltuid -replace '^(\d{2})\d+(\d{2})$', '$1****$2'
	$Embed.title = $display_name -replace '\*', '\*'

	# Parse cookies into jar
	$jar = @{}
	foreach ($c in ($Cookie -split ';')) {
		$c = $c.Trim()
		if ($c) {
			$c_pair = $c -split '=', 2
			$jar[$c_pair[0]] = $c_pair[1]
		}
	}

	# Get detailed account info
	$ac_info = Get-HoyolabAccountInfo -Cookies $jar -UserAgent $Config.user_agent -Config $Config
	if ($ac_info.Success) {
		$display_name = $ac_info.DisplayName
		$Embed.title = $display_name -replace '\*', '\*'
		$Embed.description = ""
	}
	else {
		$Embed.description = $ac_info.Message
		Write-Log -Level 'ERROR' -Message "Failed to get account info for ${ltuid}: $($ac_info.Message)"
		return @{ NeedPing = $true }
	}

	$any_ping = $false
	foreach ($game in $Config.games) {
		Write-Log -Level 'DEBUG' -Message "Signing for: $($game.name)"

		$act_id = $game.act_id
		$base_url = 'https://' + $game.domain
		$api_headers = @{
			'Accept'            = 'application/json, text/plain, */*'
			'Accept-Encoding'   = 'gzip, deflate, br'
			'Accept-Language'   = 'en-US,en;q=0.9'
			'x-rpc-app_version' = '2.34.1'
			'x-rpc-client_type' = '4'
			'Sec-Fetch-Site'    = 'same-site'
			'Sec-Fetch-Mode'    = 'cors'
			'Sec-Fetch-Dest'    = 'empty'
			'sec-ch-ua'         = '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"'
			'sec-ch-ua-mobile'  = '?0'
			'Origin'            = $game.origin_url
			'Referer'           = $game.referer_url
		}
		if ($game.custom_headers) {
			$game.custom_headers.psobject.properties | Foreach { $api_headers[$_.Name] = $_.Value }
		}

		$session = New-WebSession -Cookies $jar -For $base_url

		# 1. Get info
		$api_info_url = "$base_url/event/$($game.game_id)/info?lang=$($Config.lang)&act_id=$act_id"
		$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $api_headers -ContentType 'application/json;charset=UTF-8' -UserAgent $Config.user_agent -WebSession $session
		Write-Log -Level 'DEBUG' -Message "Queried info: $ret_info data: $($ret_info.data)"

		if ($ret_info.retcode -eq -100) {
			Write-Log -Level 'ERROR' -Message "Invalid cookie for $($game.name): $ltuid"
			$Embed.fields += @{ 'name' = $game.name; 'value' = Format-Text -Text $ret_info.message; 'inline' = $true }
			$any_ping = $true
			Continue
		}

		# 2. Perform sign-in
		Write-Log -Level 'INFO' -Message "Checking $display_name in for $($game.name)"
		$api_sign_url = "$base_url/event/$($game.game_id)/sign?lang=$($Config.lang)"
		$sign_body = @{ 'act_id' = $act_id } | ConvertTo-Json
		$ret_sign = Invoke-RestMethod -Method 'Post' -Uri $api_sign_url -Body $sign_body -Headers $api_headers -ContentType 'application/json;charset=UTF-8' -UserAgent $Config.user_agent -WebSession $session
		Write-Log -Level 'DEBUG' -Message "Check-in result: $ret_sign"

		if ($ret_sign.retcode -eq -100) {
			Write-Log -Level 'ERROR' -Message "Invalid cookie during sign for $($game.name): $ltuid"
			$Embed.fields += @{ 'name' = $game.name; 'value' = Format-Text -Text $ret_sign.message; 'inline' = $true }
			$any_ping = $true
			Continue
		}

		# 3. Handle Resign
		if ($ret_info.data.sign_cnt_missed -gt 0) {
			Invoke-HoyolabResign -BaseUrl $base_url -GameId $game.game_id -ActId $act_id -Headers $api_headers -Jar $jar -Config $Config
		}

		# 4. Process sign-in outcome
		$is_already_signed = $ret_info.data.is_sign -or $ret_sign.retcode -eq -10002
		if ($is_already_signed) {
			$msg = Format-Text -Text $ret_sign.message
			Write-Log -Level 'INFO' -Message "[$display_name] $msg"
			if ($ret_sign.retcode -eq -10002) { Continue }

			# Only add to embed if not reusing message (to keep it clean)
			if ($Config.display.discord.webhook_url -and -not ($Config.display.discord.reuse_msg -match '^\d{18,}$')) {
				$Embed.fields += @{ 'name' = $game.name; 'value' = $msg; 'inline' = $true }
			}
		}
		elseif ($ret_sign.data.gt_result -and -not ($ret_sign.data.gt_result.risk_code -eq 0 -and -not $ret_sign.data.gt_result.is_risk -and $ret_sign.data.gt_result.success -eq 0)) {
			Write-Log -Level 'ERROR' -Message "Captcha requested for $ltuid ($($game.name))"
			$Embed.fields += @{ 'name' = $game.name; 'value' = $Config.display.discord.text.need_captcha; 'inline' = $true }
			$any_ping = $true
			Continue
		}
		elseif ($ret_sign.message -ne 'OK') {
			Write-Log -Level 'ERROR' -Message "Unknown check-in error for ${ltuid}: $($ret_sign.message)"
			Continue
		}
		else {
			# Success - get updated info
			$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $api_headers -ContentType 'application/json;charset=UTF-8' -UserAgent $Config.user_agent -WebSession $session
		}

		# 5. Get Reward Info
		$api_reward_url = "$base_url/event/$($game.game_id)/home?lang=$($Config.lang)&act_id=$act_id"
		$ret_reward = Invoke-RestMethod -Method 'Get' -Uri $api_reward_url -Headers $api_headers -ContentType 'application/json;charset=UTF-8' -UserAgent $Config.user_agent -WebSession $session
		if (($ret_info.retcode -eq -100) -or ($ret_reward.retcode -eq -100)) {
			$Embed.description = Format-Text -Text $ret_reward.message
			Continue
		}

		$current_reward = $ret_reward.data.awards[$ret_info.data.total_sign_day - 1]
		$reward_name = Format-Text -Text $current_reward.name
		Write-Log -Level 'INFO' -Message "[$display_name] $reward_name x$($current_reward.cnt)"

		$Embed.color = '5635840' # Green (Success)
		$reward_text = if ($Config.display.discord.text.minimal) {
			"$($ret_info.data.today) ($($ret_info.data.total_sign_day))`n$reward_name x$($current_reward.cnt)"
		}
		else {
			"$($ret_info.data.today)`n**$($Config.display.discord.text.total_sign_day)**`n$($ret_info.data.total_sign_day)$($Config.display.discord.text.total_sign_day_unit)`n**$($Config.display.discord.text.reward)**`n$reward_name x$($current_reward.cnt)"
		}
		$Embed.fields += @{ 'name' = $game.name; 'value' = $reward_text; 'inline' = $true }
	}

	return @{ NeedPing = $any_ping }
}

function Invoke-HoyolabResign {
	param($BaseUrl, $GameId, $ActId, $Headers, $Jar, $Config)

	$lang = $Config.lang
	$user_agent = $Config.user_agent

	$api_tasks_url = "$BaseUrl/event/$GameId/task/list?act_id=$ActId&lang=$lang"
	$api_task_complete_url = "$BaseUrl/event/$GameId/task/complete"
	$api_task_award_url = "$BaseUrl/event/$GameId/task/award"

	$session = New-WebSession -Cookies $Jar -For $BaseUrl
	$ret_tasks = Invoke-RestMethod -Method 'Get' -Uri $api_tasks_url -Headers $Headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session

	foreach ($task in $ret_tasks.data.list) {
		if ($task.status -eq "TT_Award") { Continue }
		$body = @{ "id" = $task.id; "lang" = $lang; "act_id" = $ActId } | ConvertTo-Json
		Invoke-RestMethod -Method 'Post' -Uri $api_task_complete_url -Headers $Headers -Body $body -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		Invoke-RestMethod -Method 'Post' -Uri $api_task_award_url -Headers $Headers -Body $body -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
	}

	$api_resign_info_url = "$BaseUrl/event/$GameId/resign_info?act_id=$ActId&lang=$lang"
	$ret_resign_info = Invoke-RestMethod -Method 'Get' -Uri $api_resign_info_url -Headers $Headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session

	if (($ret_resign_info.data.resign_cnt_monthly -lt $ret_resign_info.data.resign_limit_monthly) -and ($ret_resign_info.data.resign_cnt_daily -lt $ret_resign_info.data.resign_limit_daily)) {
		$body = @{ "act_id" = $ActId; "lang" = $lang } | ConvertTo-Json
		Invoke-RestMethod -Method 'Post' -Uri "$BaseUrl/event/$GameId/resign" -Headers $Headers -Body $body -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
	}
}

####################
# Main
####################

$conf = Get-Content .\sign.json -Raw -Encoding 'UTF8' | ConvertFrom-Json
$global:debugging = $env:debug -eq 'pwsh-hoyolab-checkin'

# Check Discord message reuse
if ($conf.display.discord.webhook_url -and $conf.display.discord.reuse_msg -match '^(\d{18,})(len\d+)?$') {
	$dc_reuse_id = $Matches.1
	$ret = Invoke-RestMethod -Method 'Get' -Uri "$($conf.display.discord.webhook_url)/messages/$dc_reuse_id" -ContentType 'application/json;charset=UTF-8'
	if ($ret.embeds.Length -ne $conf.cookies.Length) {
		Write-Log -Level 'WARN' -Message 'Config has been changed (number of cookies). Will not re-use the previous message.'
		$conf.display.discord.reuse_msg = "true"
	}
}

$discord_embeds = @()
$any_need_ping = $false

foreach ($cookie in $conf.cookies) {
	$embed = Initialize-DiscordEmbed
	$discord_embeds += $embed

	$result = Invoke-HoyolabCheckin -Cookie $cookie -Config $conf -Embed $embed
	if ($null -ne $result -and $result.NeedPing) { $any_need_ping = $true }
}

# Final Notifications
if ($discord_embeds.Count) {
	Send-DiscordNotification -Config $conf -Embeds $discord_embeds -NeedPing $any_need_ping -PingString (Get-DiscordPing -PingConfig $conf.display.discord.ping)
}

if ($conf.display.console -eq 'pause') {
	Write-Log -Level 'INFO' -Message 'Press ENTER to continue ...'
	Read-Host
}