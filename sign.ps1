Add-Type -AssemblyName PresentationFramework

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

$conf = Get-Content .\sign.json -Raw -Encoding 'UTF8' | ConvertFrom-Json
$lang = $conf.lang
$act_id = $conf.act_id
$base_url = 'https://hk4e-api-os.mihoyo.com'
$user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'
$referer_url = "https://webstatic-sea.mihoyo.com/ys/event/signin-sea/index.html?act_id=$act_id"
$path_api_reward = "/event/sol/home?lang=$lang&act_id=$act_id"
$path_api_info = "/event/sol/info?lang=$lang&act_id=$act_id"
$path_api_sign = "/event/sol/sign?lang=$lang"
$sign_body = @{
	'act_id' = $act_id
}
if ($conf.discord_webhook_url) {
	$discord_embed = @()
}
if ($conf.popup) {
	$popup_msg = ''
}

$first_cookie = $true
foreach ($cookie in $conf.cookies) {
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
		'Origin'           = 'https://webstatic-sea.mihoyo.com'
		'Sec-Fetch-Site'   = 'same-site'
		'Sec-Fetch-Mode'   = 'cors'
		'Sec-Fetch-Dest'   = 'empty'
		'Referer'          = $referer_url
		'Accept-Language'  = 'en-US,en;q=0.9'
	}

	if (($cookie -match 'ltoken=[0-9a-zA-Z]{40}') -and ($cookie -match 'ltuid=(\d+)')) {
		# Basic check if cookie valid
		$uid = $Matches.1
		if ($conf.show_ltuid) {
			$display_uid = "LTUID: $uid"
		}
		else {
			$display_uid = 'Hidden'
		}
		Write-Host "Signing for $display_uid"
		$ret_info = Invoke-RestMethod -Method 'Get' -Uri ($base_url + $path_api_info) -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
		if ($ret_info.retcode -ne -100) {
			# If server found valid cookie
			$ret_sign = Invoke-RestMethod -Method 'Post' -Uri ($base_url + $path_api_sign) -Body ($sign_body | ConvertTo-Json) -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
			if ($ret_sign.retcode -ne -100) {
				# If server found valid cookie
				if ($conf.popup -and (($ret_info.data.is_sign -and $conf.duplicated_sign) -or ((-not $ret_info.data.is_sign) -and ($ret_sign.message -eq 'OK')))) {
					if ($first_cookie) {
						$first_cookie = $false
					}
					else {
						$popup_msg += "`n"
					}
				}
				if ($ret_info.data.is_sign -and $conf.duplicated_sign) {
					# If sign is duplicated and need to be shown
					$msg = Format-Text -Text $ret_sign.message
					if ($conf.popup) {
						$popup_msg += "[$display_uid] $msg"
					}
					if ($conf.discord_webhook_url) {
						$discord_embed += @{
							'title'  = $msg
							'color'  = '16711680'
							'footer' = @{
								'text' = $display_uid
							}
						}
					}
				}
				if ((-not $ret_info.data.is_sign) -and ($ret_sign.message -eq 'OK')) {
					$ret_info = Invoke-RestMethod -Method 'Get' -Uri ($base_url + $path_api_info) -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
					$ret_reward = Invoke-RestMethod -Method 'Get' -Uri ($base_url + $path_api_reward) -Headers $headers -ContentType 'application/json;charset=UTF-8' -UserAgent $user_agent -WebSession $session
					$current_reward = $ret_reward.data.awards[$ret_info.data.total_sign_day - 1] # Array start from 0
					$reward_name = Format-Text -Text $current_reward.name
					if ($conf.popup) {
						$popup_msg += "[$display_uid] $reward_name x$($current_reward.cnt)"
					}
					if ($conf.discord_webhook_url) {
						$discord_embed += @{
							# 'title'  = $ret_info.data.today
							'fields' = @(
								@{
									'name'   = 'Total sign days'
									'value'  = $ret_info.data.total_sign_day
									'inline' = $true
								},
								@{
									'name'   = 'Reward'
									'value'  = "$reward_name x$($current_reward.cnt)"
									'inline' = $true
								}
							)
							'thumbnail'  = @{
								'url' = $current_reward.icon
							}
							'color'  = '5635840'
							'footer' = @{
								'text' = "$($ret_info.data.today) | $display_uid"
							}
						}
					}
				}
			}
			else {
				[System.Windows.MessageBox]::Show("${uid}: Invalid cookie. ($($ret_sign))")
			}
		}
		else {
			[System.Windows.MessageBox]::Show("${uid}: Invalid cookie ($($ret_info))")
		}
	}
	else {
		[System.Windows.MessageBox]::Show("Invalid cookie: $cookie")
	}
}

if ($conf.discord_webhook_url -and $discord_embed.Count) {
	$discord_body = @{
		'embeds' = $discord_embed
	}
	if ($conf.discord_webhook_username) {
		$discord_body.username = $conf.discord_webhook_username
	}
	if ($conf.discord_webhook_avatar_url) {
		$discord_body.avatar_url = $conf.discord_webhook_avatar_url
	}
	if ($conf.reuse_discord_msg) {
		if ($conf.reuse_discord_msg -match '^\d{18,}$') {
			$ret_discord = Invoke-RestMethod -Method 'Patch' -Uri "$($conf.discord_webhook_url)/messages/$($conf.reuse_discord_msg)" -Body ($discord_body | ConvertTo-Json -Depth 10) -ContentType 'application/json;charset=UTF-8'
		}
		else {
			$ret_discord = Invoke-RestMethod -Method 'Post' -Uri ($conf.discord_webhook_url + '?wait=true') -Body ($discord_body | ConvertTo-Json -Depth 10) -ContentType 'application/json;charset=UTF-8'
			$conf.reuse_discord_msg = $ret_discord.id
			$conf | ConvertTo-Json | Set-Content .\sign.json -Encoding 'UTF8'
		}
	}
	else {
		$ret_discord = Invoke-RestMethod -Method 'Post' -Uri $conf.discord_webhook_url -Body ($discord_body | ConvertTo-Json -Depth 10) -ContentType 'application/json;charset=UTF-8'
	}
}
if ($conf.popup -and $popup_msg) {
	[System.Windows.MessageBox]::Show($popup_msg)
}
