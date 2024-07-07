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
$dc_webhook = $conf.display.discord.webhook_url -ne ''
$dc_reuse = $conf.display.discord.reuse_msg -and $conf.display.discord.reuse_msg -match '^(\d{18,})(len\d+)?$'
$dc_reuse_id = $Matches.1
$conf.display.discord.reuse_msg = $dc_reuse_id

if ($dc_webhook) {
	if ($env:debug -eq 'pwsh-hoyolab-checkin.discord') {
		Write-Host '[DEBUG] Webhook as' $conf.display.discord.username
	}
	$discord_embed = @()
	if ($conf.display.discord.ping) {
		$discord_need_ping = $false
		$discord_ping = ""
		if ($conf.display.discord.ping.user) {
			$discord_ping += "<@" + ($conf.display.discord.ping.user -join "> <@") + ">"
		}
		if ($conf.display.discord.ping.user -and $conf.display.discord.ping.role) {
			$discord_ping += " "
		}
		if ($conf.display.discord.ping.role) {
			$discord_ping += "<@&" + ($conf.display.discord.ping.role -join "> <@&") + ">"
		}
		if ($env:debug -eq 'pwsh-hoyolab-checkin.discord') {
			Write-Host "[DEBUG] ID that will be ping: " $discord_ping
		}
	}
	if ($dc_reuse) {
		$ret_discord = Invoke-RestMethod -Method 'Get' -Uri "$($conf.display.discord.webhook_url)/messages/$dc_reuse_id" -ContentType 'application/json;charset=UTF-8'
		if ($env:debug -eq 'pwsh-hoyolab-checkin.discord') {
			Write-Host "[DEBUG] Previous message to be reused:`nEmbed length: $($ret_discord.embeds.Length) (expect: $($conf.cookies.Length))`n" ( $ret_discord.embeds | ConvertTo-Json -Depth 10 ) # avoid id outputs
		}
		if ($ret_discord.embeds.Length -ne $conf.cookies.Length) {
			$dc_reuse_id = "true"
			Write-Host '[WARN] Config has been changed. Will not re-use the previous message.'
		}
	}
}

####################
# Main
####################

foreach ($cookie in $conf.cookies) {
	if ($dc_webhook) {
		$discord_embed += @{
			'color'       = '16711680'
			'title'       = "ERROR"
			'description' = "Unknown error. Maybe invalid cookie."
			'fields'      = @()
		}
		if ($env:debug -eq 'pwsh-hoyolab-checkin.discord') {
			Write-Host "[DEBUG] Adding embed:`n" ( $discord_embed[-1] | ConvertTo-Json -Depth 2 )
		}
	}

	# Basic check if cookie valid
	if ($cookie -like "*ltoken_v2=*") {
		if (-not(($cookie -match 'ltoken_v2=v2_[^\s;]{114,}') -and ($cookie -match 'ltmid_v2=[0-9a-zA-Z_]{13}') -and ($cookie -match 'ltuid_v2=(\d+)'))) {
			Write-Host "[ERROR] Invalid cookie format: $cookie"
			Continue
		}
	}
	else {
		if (-not(($cookie -match 'ltoken=[0-9a-zA-Z]{40}') -and ($cookie -match 'ltuid=(\d+)'))) {
			Write-Host "[ERROR] Invalid cookie format: $cookie"
			Continue
		}
	}
	
	$ltuid = $Matches.1
	$display_name = $ltuid -replace '^(\d{2})\d+(\d{2})$', '$1****$2'
	$discord_embed[-1].title = $display_name -replace '\*', '\*'
	
	# Cookies setup
	$jar = @{}
	foreach ($c in ($cookie -split ';')) {
		$c = $c.Trim()
		if ($c) {
			$c_pair = $c -split '=', 2
			$jar[$c_pair[0]] = $c_pair[1]
		}
	}
	
	# Get account info
	$session = New-WebSession -Cookies $jar -For 'https://api-account-os.hoyolab.com'
	$headers = @{
		'Accept'           = 'application/json, text/plain, */*'
		'Accept-Language'  = 'en-US,en;q=0.9'
		'Origin'           = 'https://act.hoyolab.com'
		'Referer'          = 'https://act.hoyolab.com/'
		'sec-ch-ua'        = '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"'
		'sec-ch-ua-mobile' = '?0'
		'Sec-Fetch-Site'   = 'same-site'
		'Sec-Fetch-Mode'   = 'cors'
		'Sec-Fetch-Dest'   = 'empty'
	}
	$ret_ac_info = Invoke-RestMethod -Method 'Get' -Uri 'https://api-account-os.hoyolab.com/auth/api/getUserAccountInfoByLToken' -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
	if ($debugging) {
		Write-Host
		Write-Host '[DEBUG] Account info:' $ret_ac_info 'data:' $ret_ac_info.data
	}
	if ($ret_ac_info.retcode -eq -0) {
		$display_name = ''
		if ($conf.display.account_info.name -and $ret_ac_info.data.account_name) {
			$display_name = $ret_ac_info.data.account_name
		}
		elseif ($conf.display.account_info.email -and $ret_ac_info.data.email) {
			$display_name = $ret_ac_info.data.email
		}
		elseif ($conf.display.account_info.id -and $ret_ac_info.data.account_id) {
			$display_name = $ret_ac_info.data.account_id
		}
		elseif ($conf.display.account_info.phone -and $ret_ac_info.data.mobile) {
			$display_name = $ret_ac_info.data.mobile
		}
		$discord_embed[-1].title = $display_name -replace '\*', '\*'
	}
	else {
		if ($dc_webhook) {
			$discord_need_ping = $true
			$discord_embed[-1].description = $ret_ac_info.message
		}
		Continue
	}
	
	if ($dc_webhook) { $discord_embed[-1].description = '' }
	
	foreach ($game in $conf.games) {
		if ($debugging) {
			Write-Host
			Write-Host '[DEBUG] Signing for:' $game
		}
		# URL setup
		$act_id = $game.act_id
		$base_url = 'https://' + $game.domain
		$api_reward_url = "$base_url/event/$($game.game_id)/home?lang=$lang&act_id=$act_id"
		$api_info_url = "$base_url/event/$($game.game_id)/info?lang=$lang&act_id=$act_id"
		$api_sign_url = "$base_url/event/$($game.game_id)/sign?lang=$lang"

		# Web Session setup
		$session = New-WebSession -Cookies $jar -For $base_url
		$headers = @{
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

		# Query info about check-in
		$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host '[DEBUG] Queried info:' $ret_info 'data:' $ret_info.data
		}
		if ($ret_info.retcode -eq -100) {
			if ($conf.display.console -or $debugging) {
				Write-Host "[ERROR] Invalid cookie: $ltuid ($ret_info)"
			}
			if ($dc_webhook) {
				$discord_embed[-1].fields += @{
					'name'   = $game.name
					'value'  = Format-Text -Text $ret_info.message
					'inline' = $true
				}
			}
			Continue
		}

		# Request check-in
		if ($conf.display.console -or $debugging) {
			Write-Host "[INFO] Checking $display_name in for $($game.name)"
		}
		$sign_body = @{
			'act_id' = $act_id
		} | ConvertTo-Json
		$ret_sign = Invoke-RestMethod -Method 'Post' -Uri $api_sign_url -Body $sign_body -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host '[DEBUG] Check-in:' $ret_sign 'data:' $ret_sign.data 'gt_result:' $ret_sign.data.gt_result
		}
		if ($ret_sign.retcode -eq -100) {
			if ($conf.display.console -or $debugging) {
				Write-Host "[ERROR] Invalid cookie: $ltuid ($ret_sign)"
			}
			if ($dc_webhook) {
				$discord_embed[-1].fields += @{
					'name'   = $game.name
					'value'  = Format-Text -Text $ret_sign.message
					'inline' = $true
				}
			}
			Continue
		}

		# Already checked-in in the same day
		# No account created
		if ($ret_info.data.is_sign -or $ret_sign.retcode -eq -10002) {
			$msg = Format-Text -Text $ret_sign.message
			if ($conf.display.console -or $debugging) {
				Write-Host "[INFO] [$display_name] $msg"
			}
			if ($ret_sign.retcode -eq -10002) {
				Continue
			}
			# No overwrite on old message
			if ($dc_webhook -and -not $dc_reuse) {
				$discord_embed[-1].fields += @{
					'name'   = $game.name
					'value'  = $msg
					'inline' = $true
				}
			}
		}
		# Check if captcha needed
		elseif ($ret_sign.data.gt_result -and -not ($ret_sign.data.gt_result.risk_code -eq 0 -and -not $ret_sign.data.gt_result.is_risk -and $ret_sign.data.gt_result.success -eq 0)) {
			if ($conf.display.console -or $debugging) {
				Write-Host "[ERROR] Captcha requested: $ltuid (" $ret_sign.data.gt_result ")"
			}
			if ($dc_webhook) {
				$discord_need_ping = $true
				$discord_embed[-1].fields += @{
					'name'   = $game.name
					'value'  = $conf.display.discord.text.need_captcha
					'inline' = $true
				}
			}
			Continue
		}
		# Unknown not checked-in situation
		elseif ($ret_sign.message -ne 'OK') {
			# use elseif to avoid skip when debug
			if ($conf.display.console -or $debugging) {
				Write-Host "[ERROR] [$ltuid] Unknown check-in error: $ret_sign"
			}
			Continue
		}
		# Get new info after checked-in
		else {
			$ret_info = Invoke-RestMethod -Method 'Get' -Uri $api_info_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		}
		$ret_reward = Invoke-RestMethod -Method 'Get' -Uri $api_reward_url -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($debugging) {
			Write-Host '[DEBUG] Queried checkin info:' $ret_info 'data:' $ret_info.data
			Write-Host '[DEBUG] Queried reward info:' $ret_reward 'data:' $ret_reward.data
		}
		if (($ret_info.retcode -eq -100) -or ($ret_reward.retcode -eq -100)) {
			if ($conf.display.console -or $debugging) {
				Write-Host "[ERROR] Invalid cookie format: $cookie"
			}
			if ($dc_webhook) {
				$discord_embed[-1].description = Format-Text -Text $ret_reward.message
			}
			Continue
		}

		$current_reward = $ret_reward.data.awards[$ret_info.data.total_sign_day - 1] # Array start from 0
		$reward_name = Format-Text -Text $current_reward.name
		if ($conf.display.console -or $debugging) {
			Write-Host "[INFO] [$display_name] $reward_name x$($current_reward.cnt)"
		}
		if ($dc_webhook) {
			$discord_embed[-1].color = '5635840'
			$discord_embed[-1].fields += @{
				'name'   = $game.name
				'value'  = $(if ($conf.display.discord.text.minimal) {
						"$($ret_info.data.today) ($($ret_info.data.total_sign_day))
						$reward_name x$($current_reward.cnt)"
					}
					else { 
						"$($ret_info.data.today)
						**$($conf.display.discord.text.total_sign_day)**
						$($ret_info.data.total_sign_day)$($conf.display.discord.text.total_sign_day_unit)
						**$($conf.display.discord.text.reward)**
						$reward_name x$($current_reward.cnt)"
					}) 
				'inline' = $true
			}
		}
	}
}

if ($dc_webhook -and $discord_embed.Count) {
	$discord_body = @{
		'content' = ''
		'embeds'  = $discord_embed
	}
	if ($conf.display.discord.username) {
		$discord_body.username = $conf.display.discord.username
	}
	if ($conf.display.discord.avatar_url) {
		$discord_body.avatar_url = $conf.display.discord.avatar_url
	}
	$discord_body_json = $discord_body | ConvertTo-Json -Depth 10
	if ($env:debug -eq 'pwsh-hoyolab-checkin.discord') {
		Write-Host "[DEBUG] Discord message body:`n" $discord_body_json
	}
	if ($dc_reuse) {
		if ($dc_reuse_id -match '^\d{18,}$') {
			$ret_discord = Invoke-WebRequest -Method 'Patch' -Uri "$($conf.display.discord.webhook_url)/messages/$dc_reuse_id" -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
		}
		else {
			$ret_discord = Invoke-RestMethod -Method 'Post' -Uri ($conf.display.discord.webhook_url + '?wait=true') -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
			$conf.display.discord.reuse_msg = $ret_discord.id
			$conf | ConvertTo-Json -Depth 10 | Set-Content .\sign.json -Encoding 'UTF8'
		}
	}
	else {
		$ret_discord = Invoke-RestMethod -Method 'Post' -Uri $conf.display.discord.webhook_url -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
	}
	if ($discord_need_ping) {
		$discord_body.content = $discord_ping
		$discord_body.embeds = $null
		$discord_body_json = $discord_body | ConvertTo-Json -Depth 10
		$ret_discord = Invoke-RestMethod -Method 'Post' -Uri $conf.display.discord.webhook_url -Body $discord_body_json -ContentType 'application/json;charset=UTF-8'
	}
}

if ($conf.display.console -eq 'pause') {
	Write-Host '[INFO] Press ENTER to continue ...'
	Read-Host
}