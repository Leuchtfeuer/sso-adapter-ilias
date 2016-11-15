<?php
/*
* DirectSSO Single Sign-On Framework
* SSO Adapter for
* ILIAS (http://www.ilias.de)
*
*  Version            				: 0.4.0
*  Last update      				: 24.10.2016
*  Developed against App version	: 5.0.5
*
*  (c) Bitmotion GmbH, Hannover, Germany
*  http://www.single-signon.com
*/

ini_set('display_errors', 1);
if(version_compare(PHP_VERSION, '5.4.0', '>='))
{
	// Prior to PHP 5.4.0 E_ALL does not include E_STRICT.
	// With PHP 5.4.0 and above E_ALL >DOES< include E_STRICT.

	error_reporting(((ini_get("error_reporting") & ~E_NOTICE) & ~E_DEPRECATED) & ~E_STRICT);
}
elseif(version_compare(PHP_VERSION, '5.3.0', '>='))
{
	error_reporting((ini_get("error_reporting") & ~E_NOTICE) & ~E_DEPRECATED);
}
else
{
	error_reporting(ini_get('error_reporting') & ~E_NOTICE);
}
chdir(realpath(dirname(__FILE__)));

// Configure client id
$config['client_id'] = 'ssodemo';
$client_dirs         = glob("./data/*", GLOB_ONLYDIR);
foreach((array)$client_dirs as $dir)
{
	if(file_exists($dir . '/client.ini.php') && is_readable($dir . '/client.ini.php'))
	{
		$ini = @parse_ini_file($dir . '/client.ini.php', true);
		if(is_array($ini) && isset($ini['client']) && isset($ini['client']['name']) && strlen($ini['client']['name']))
		{
			$config['client_id'] = $ini['client']['name'];
			break;
		}
	}
}

require_once 'Services/Context/classes/class.ilContext.php';
ilContext::init(ilContext::CONTEXT_REST);
set_include_path(get_include_path() . ':' . realpath(dirname(__FILE__)));
require_once 'include/inc.header.php';
require_once 'Services/User/classes/class.ilObjUser.php';
require_once 'Services/Authentication/classes/class.ilSession.php';

/**
 * @var $ilSetting ilSetting
 * @var $ilDB      ilDB
 */
global $ilSetting, $ilDB;

/**
 * Return the protocol version
 * @return string
 */
function get_version()
{
	return "2.0";
}

/**
 *  Function which is called after including this file in the SSO-Agent.
 * @param
 *    User_Name    string    Username the Session will be created for
 *    remote_addr  string    Remoteaddress of the users system
 *    agent        string    Browser
 *    sso_url      string    Url where the user will be redirected after establishing a session for him
 *    sso_version  string    The protocol version of the calling agent
 *    sso_action   string    The action to perform. Right now this is either 'logon' or 'create_modify'
 *    sso_userdata array     The userdata submitted by the agent
 * @return         string    Return the session data
 *    Leave stubs if you dont need all four params.
 */
function sso($User_Name, $ip, $agent, $sso_url, $sso_version = "", $sso_action = "", $sso_userdata = array())
{
	global $config, $ilDB, $ilSetting;
	$config['client_id'] = 'ssodemo';

	if($sso_version == '')
	{
		return array('Error' => 'sso version out of date');
	}

	$usr_id = ilObjUser::_loginExists($User_Name);

	// Parse the submitted groups where the user is a member
	//$sso_groups = explode(',', $sso_userdata['usergroup']);

	switch($sso_action)
	{
		// Action: create user / update userdata
		case 'create_modify':
			// User does not exist yet
			if(!$usr_id)
			{
				$userData = array(
					'login'                => $User_Name,
					'email'                => $sso_userdata['email'],
					'active'               => 1,
					'passwd_type'          => IL_PASSWD_PLAIN,
					'auth_mode'            => 'default',
					'time_limit_unlimited' => 1,
				);
				$userData = array_merge($userData, (array)$sso_userdata);

				$userObj = new ilObjUser();
				$userObj->assignData($userData);
				$userObj->create();
				$userObj->saveAsNew();
				$userObj->setLastPasswordChangeToNow();

				require_once "./Services/AccessControl/classes/class.ilRbacReview.php";
				require_once "./Services/AccessControl/classes/class.ilRbacSystem.php";
				require_once "./Services/AccessControl/classes/class.ilRbacAdmin.php";

				/**
				 * @var $rbacadmin ilRbacAdmin
				 */
				global $rbacadmin;

				$rbacreview            = new ilRbacReview();
				$GLOBALS['rbacreview'] = $rbacreview;

				$rbacsystem            = ilRbacSystem::getInstance();
				$GLOBALS['rbacsystem'] = $rbacsystem;

				$rbacadmin            = new ilRbacAdmin();
				$GLOBALS['rbacadmin'] = $rbacadmin;

				$GLOBALS['rbacadmin']->assignUser(4, $userObj->getId());
			}
			else
			{
				// User already exists, update profile with data from TYPO3's fe_users
				$userObj = new ilObjUser($usr_id);
				// Data used from fe_users: email, country, website
				$remove_auth = false;
				if(!isset($GLOBALS['ilAuth']))
				{
					require_once 'Services/PEAR/lib/Auth.php';
					if(!class_exists('ilTmpAuth'))
					{
						class ilTmpAuth extends Auth
						{
							protected $myusername = '';
							public function __construct()
							{
							}
							public function getUserName()
							{
								return $this->myusername;
							}
							public function setUserName($username)
							{
								$this->myusername = $username;
							}
						}
					}
					$tmpauth = new ilTmpAuth();
					$tmpauth->setUserName($userObj->getLogin());
					$tmpauth->setAuth($userObj->getLogin());
					$GLOBALS['ilAuth'] = $tmpauth;
				}
				// @todo
				//$userObj->assignData(array_merge(array('passwd_type' => IL_PASSWD_PLAIN), (array)$sso_userdata));
				$userObj->update();
				if($remove_auth)
				{
					unset($GLOBALS['ilAuth']);
				}
			}
			break;
		// Perform logon for given $User_Name
		case 'logon':
			if(!$usr_id)
			{
				return array('Error' => 'No account for this user');
			}
			else
			{
				$user = new ilObjUser($usr_id);
				if(!$user->getActive())
				{
					return array("Error" => 'Account inactive: ' . $user->getLogin() . ' (' . $user->getId() . '), denied access');
				}

				if(!$user->checkTimeLimit())
				{
					return array("Error" => 'Time limit exceeded: ' . $user->getLogin() . ' (' . $user->getId() . '), denied access');
				}

				$clientip = $user->getClientIP();
				if(trim($clientip) != '')
				{
					$clientip = preg_replace("/[^0-9.?*,:]+/", "", $clientip);
					$clientip = str_replace(".", "\\.", $clientip);
					$clientip = str_replace(Array("?", "*", ","), Array("[0-9]", "[0-9]*", "|"), $clientip);
					if(!preg_match("/^" . $clientip . "$/", $_SERVER["REMOTE_ADDR"]))
					{
						return array('Error' => 'Wrong ip: ' . $user->getLogin() . ' (' . $user->getId() . '), denied access');
					}
				}

				if(
					$ilSetting->get('ps_prevent_simultaneous_logins') &&
					ilObjUser::hasActiveSession($user->getId())
				)
				{
					return array('Error' => 'Simultaneous login: ' . $user->getLogin() . ' (' . $user->getId() . '), denied access');
				}

				require_once 'Services/PEAR/lib/Auth.php';
				$auth = new Auth('', '', '', FALSE);
				$auth->setAuth($user->getLogin());
				$_SESSION['_auth__authhttp' . md5($config['client_id'])] = $_SESSION['_authsession'];

				$fields = array(
					'createtime' => array("integer", time()),
					"user_id"    => array("integer", $user->getId()),
					"expires"    => array("integer", ilSession::getExpireValue()),
					"data"       => array("clob", serialize($_SESSION)),
					"ctime"      => array("integer", time()),
					"type"       => array("integer", 0)
				);
				$ilDB->replace("usr_session", array("session_id" => array("text", session_id())), $fields);

				$return_val = array(
					0             => array(
						'CookieName'  => 'ilClientId',
						'CookieValue' => $config['client_id'],
					),
					1             => array(
						'CookieName'  => 'iltest',
						'CookieValue' => 'cookie',
					),
					"redirecturl" => $sso_url,
				);

				ilObjUser::_updateLastLogin($user->getId());

				return $return_val;
			}
			break;
		case 'logoff':
			if(!$usr_id) {
				return array('Error' => 'No account for this user');
			} else {
				$ilDB->manipulate("DELETE FROM usr_session WHERE user_id = " . $ilDB->quote($usr_id, "integer"));
			}
			break;
	}
}
