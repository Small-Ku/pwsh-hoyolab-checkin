####################
# Functions
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

	if ($PSVersionTable.PSVersion.Major -le 5) {
		$bytes = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetBytes($Text)
		return [System.Text.Encoding]::UTF8.GetString($bytes)
	}

	return $Text
}

####################
# Configs
####################

$conf = Get-Content .\sign.json -Raw -Encoding 'UTF8' | ConvertFrom-Json
$lang = $conf.lang
$user_agent = $conf.user_agent
$debugging = $env:debug -eq 'pwsh-hoyolab-checkin'

if ($conf.notification.discord.webhook_url) {
	$discord_embed = @()
}

####################
# Main
####################

foreach ($cookie in $conf.cookies) {
	# Basic check if cookie valid
	if (-not(($cookie -match 'ltoken=[0-9a-zA-Z]{40}') -and ($cookie -match 'ltuid=(\d+)'))) {
			Write-Host "Invalid cookie format: $cookie"
		Continue
	}
	$ltuid = $Matches.1
	
	foreach ($game in $conf.games) {
		if ($debugging) {
			Write-Host 'Signing for:' $game
		}
		# URL setup
		$act_id = $game.act_id
		$base_url = 'https://' + $game.domain
		$api_reward_url = "$base_url/event/$($game.game_id)/home?lang=$lang&act_id=$act_id"
		$api_info_url = "$base_url/event/$($game.game_id)/info?lang=$lang&act_id=$act_id"
		$api_sign_url = "$base_url/event/$($game.game_id)/sign?lang=$lang"

		# Web Session / Cookies setup
		$jar = @{}
		foreach ($c in ($cookie -split ';')) {
			$c = $c.Trim()
			if ($c) {
				$c_pair = $c -split '=', 2
				$jar[$c_pair[0]] = $c_pair[1]
			}
		}
		$session = New-WebSession -Cookies $jar -For $base_url
		$headers = @{
			'sec-ch-ua'        = '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"'
			'Accept'           = 'application/json, text/plain, */*'
			'sec-ch-ua-mobile' = '?0'
			'Origin'           = $game.origin_url
			'Sec-Fetch-Site'   = 'same-site'
			'Sec-Fetch-Mode'   = 'cors'
			'Sec-Fetch-Dest'   = 'empty'
			'Referer'          = $game.referer_url
			'Accept-Language'  = 'en-US,en;q=0.9'
		}

		# Query info about check-in
		$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host 'Queried info:' $ret_info 'data:' $ret_info.data
		}
		if ($ret_info.retcode -eq -100) {
				Write-Host "Invalid cookie format: $cookie"
			Continue
		}

		# Request check-in
		Write-Host "Checking $ltuid in for $($game.name)"
		$sign_body = @{
			'act_id' = $act_id
		} | ConvertTo-Json
		$ret_sign = Invoke-RestMethod -Method 'Post' -Uri $api_sign_url -Body $sign_body -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host 'Check-in:' $ret_sign 'data:' $ret_sign.data
		}
		if ($ret_sign.retcode -eq -100) {
				Write-Host "Invalid cookie: $ltuid ($ret_sign)"
			Continue
		}

		# Already checked-in before
		if ($ret_info.data.is_sign) {
			$msg = Format-Text -Text $ret_sign.message
				Write-Host "[$ltuid] $msg"
			if (-not $debugging)	{ Continue }
		} 
		# Unknown not checked-in situation
		elseif ($ret_sign.message -ne 'OK') { # use elseif to avoid skip when debug
			Write-Host "[$ltuid] Unknown check-in error: $ret_sign"
			Continue
		}

		# Get new info after checked-in
		$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		$ret_reward = Invoke-RestMethod -Method 'Get' -Uri $api_reward_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host 'Queried checkin info:' $ret_info 'data:' $ret_info.data
			Write-Host 'Queried reward info:' $ret_reward 'data:' $ret_reward.data
		}
		if (($ret_info.retcode -eq -100) -or ($ret_reward.retcode -eq -100)) {
			Write-Host "Invalid cookie format: $cookie"
			Continue
		}
		$current_reward = $ret_reward.data.awards[$ret_info.data.total_sign_day - 1] # Array start from 0
		$reward_name = Format-Text -Text $current_reward.name
		Write-Host "[$ltuid] $reward_name x$($current_reward.cnt)"
	}
}
if ($conf.display.console_pause) {
	Write-Host "Press ENTER to continue ..."
	Read-Host
}
