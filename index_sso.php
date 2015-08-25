<?php
/*
* Signature-Based Single Sign-On Framework
* TPA Adapter for
* ILIAS (http://www.ilias.de)
*
*  Version            : 0.3.0
*  Last update        : 25.08.2015
*
*  (c) Bitmotion GmbH, Hannover, Germany
*  http://www.single-signon.com
*/

// Configure client id
$config['client_id'] = 'ilias-1';

ini_set('error_reporting', E_ALL & ~E_NOTICE & ~E_STRICT);
chdir(realpath(dirname(__FILE__)));
include_once "Services/Context/classes/class.ilContext.php";
ilContext::init(ilContext::CONTEXT_REST);
set_include_path(get_include_path() . ':' . realpath(dirname(__FILE__)));
include_once 'include/inc.header.php';
$ilDB = $GLOBALS['ilDB'];

/**
 * Return the protocol version
 * @return string
 */
function get_version() {
	return "0.3.0";
}

/**
 *  Function which is called after including this file in the SSO-Agent.
 *
 * @param
 *    User_Name    string    Username the Session will be created for
 *    remote_addr  string    Remoteaddress of the users system
 *    agent        string    Browser
 *    sso_url      string    Url where the user will be redirected after establishing a session for him
 *    sso_version  string    The protocol version of the calling agent
 *    sso_action   string    The action to perform. Right now this is either 'logon' or 'create_modify'
 *    sso_userdata array     The userdata submitted by the agent
 *
 * @return         string    Return the session data
 *
 *  Leave stubs if you dont need all four params.
 */
function sso($User_Name, $ip, $agent, $sso_url, $sso_version = "", $sso_action = "", $sso_userdata = array()) {
	global $config, $ilDB;
	if ($sso_version == "") return array("Error" => "sso version out of date");

	// Check if the given $User_Name exists in the DB
	$result = $ilDB->query(sprintf("SELECT usr_id, login FROM usr_data WHERE login = '%s';", $User_Name));
	$row = $ilDB->fetchAssoc($result);

	// Parse the submitted groups where the user is a member
	$sso_groups = explode(',', $sso_userdata['usergroup']);

	if (!empty($user)) {
		$GLOBALS['SSOuser'] = $user;
	} else {
		$user = $GLOBALS['SSOuser'];
	}

	switch ($sso_action) {
		// Action: create user / update userdata
		case 'create_modify':
			require_once("Services/User/classes/class.ilObjUser.php");
			// User does not exist yet
			if (!$row) {
				$userData = array(
					'login' => $User_Name,
					'email' => $sso_userdata['email'],
					'active' => 1,
					'passwd_type' => IL_PASSWD_PLAIN,
					'auth_mode' => 'default',
					'time_limit_unlimited' => 1,
				);
				$userData = array_merge($userData, $sso_userdata);

				$userObj = new ilObjUser();
				$userObj->assignData($userData);
				$userObj->create();
				$userObj->saveAsNew();
				$userObj->setLastPasswordChangeToNow();
			} else {
				// User already exists, update profile with data from TYPO3's fe_users
				// Data used from fe_users: email, country, website
				$userObj = new ilObjUser($row['usr_id']);
				$userObj->assignData($sso_userdata);
				$userObj->update();
			}
		break;
		// Perform logon for given $User_Name
		case 'logon':
			if (!$row) {
				// No valid user found; return error
				$error = array("Error" => "No account for this user");
				return $error;
			} else {
				require_once('Services/PEAR/lib/Auth.php');
				$auth = new Auth('', '', '', FALSE);
				$auth->setAuth($row['login']);
				$_SESSION['_auth__authhttp' . md5($config['client_id'])] = $_SESSION['_authsession'];
				$ilDB->query(sprintf('INSERT INTO usr_session (session_id, expires, data, ctime, user_id, last_remind_ts, type, createtime) VALUES (\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', 0, 2, \'%s\');',
					session_id(),
					time() + 60 * 60 * 5,
					serialize($_SESSION),
					time(),
					$row['usr_id'],
					time()));

				$return_val = array(
					0 => array(
						'CookieName' => 'ilClientId',
						'CookieValue' => $config['client_id'],
					),
					1 => array(
						'CookieName' => 'iltest',
						'CookieValue' => 'cookie',
					),
					"redirecturl" => $sso_url,
				);

				return $return_val;
			}
		break;
	}

}

?>
