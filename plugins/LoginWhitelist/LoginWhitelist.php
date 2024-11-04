<?php

class LoginWhitelist extends PluginBase
{
    protected $storage = 'DbStorage';

    protected static $description = 'Login IP Whitelist';
    protected static $name = 'LoginWhitelist';
	
    protected $settings = [
        'whitelist' => array(
            'type' => 'string',
            'label' => 'Allowed IPs',
            'help' => 'Specify one or multiple IP addresses and/or IP ranges, separated by a space. E.g. 192.168.1.1 10.0.0.0/24',
        ),
        'url' => array(
            'type' => 'string',
            'label' => 'Redirect URL',
            'help' => 'Non-whitelisted users will be redirected there, leave empty to block with 403 Forbidden error',
        ),
    ];

    public function init()
    {
        $this->subscribe('beforeLogin');
    }

    public function beforeLogin()
    {
        $whitelist = $this->get('whitelist');
        $url = $this->get('url');

        if (!empty($whitelist)) {
            $ip = $_SERVER['REMOTE_ADDR'];
            if (!$this->validateIp($ip, $whitelist)) {
                if(trim($url) != "") Yii::app()->request->redirect($url);
				else throw new CHttpException(403,Yii::t('yii','You are not authorized to perform this action.'));
            }
        }
    }

	function validateIp($ip, $whitelist) {
		$whitelist = explode(' ', $whitelist);
		foreach ($whitelist as $entry) {
			if (strpos($entry, '/') !== false) {
				// IP range
				list($range, $netmask) = explode('/', $entry);
				$rangeDec = ip2long($range);
				$ipDec = ip2long($ip);
				$netmaskDec = ~((1 << (32 - $netmask)) - 1);
				if (($ipDec & $netmaskDec) == ($rangeDec & $netmaskDec)) {
					return true;
				}
			} else {
				// Single IP address
				if ($ip == $entry) {
					return true;
				}
			}
		}
		return false;
	}

    public function getPluginSettings($getValues = true)
    {
        $pluginSettings = parent::getPluginSettings($getValues);
        return $pluginSettings;
    }
}
