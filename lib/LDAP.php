<?php
/**
 * @author Maxime Renou <contact@maximerenou.fr>
 */
namespace OCA\UserExternal;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * User authentication against a LDAP server
 *
 * @category Apps
 * @package  UserExternal
 * @author   Maxime Renou <contact@maximerenou.fr>
 * @license  http://www.gnu.org/licenses/agpl AGPL
 */
class LDAP extends Base 
{
	private $host;
	private $port;
	private $sslmode;
	private $base_dn;
	private $user_filter;
	private $user;
	private $password;

	/**
	 * Create new LDAP authentication provider
	 */
	public function __construct(
		$host = '127.0.0.1', 
		$port = 389, 
		$sslmode = false, 
		$base_dn = 'dc=domain,dc=local',
		$user_filter = '(mail=%u)',
		$user = '', 
		$password = null, 
	) {
		parent::__construct('ldap');
		$this->host = $host;
		$this->port = $port;
		$this->sslmode = $sslmode;
		$this->base_dn = $base_dn;
		$this->user_filter = $user_filter;
		$this->user = $user;
		$this->password = $password;
	}

	/**
	 * Check if the password is correct without logging in the user
	 *
	 * @param string $uid      The username
	 * @param string $password The password
	 *
	 * @return true/false
	 */
	public function checkPassword($uid, $password) 
	{
		// 1. Check user password

		$ldap = new LdapClient([
			'servers' => [
				$this->host
			],
			'port' => $this->port,
			'use_ssl' => $this->sslmode,
			'base_dn' => $this->base_dn
		]);

		try {
			if ($this->sslmode) {
				$ldap->startTls();
			}

			$ldap->bind($uid, $password);
		}
		catch (BindException $e) {
			\OC::$server->getLogger()->error(
				'LDAP: Failed to bind user ' . $uid . ': ' . $e->getMessage(),
				['app' => 'user_external']
			);
			return false;
		}
		catch (ConnectionException $e) {
			\OC::$server->getLogger()->error(
				'LDAP: Failed to connect (tried user ' . $uid . ')' . ': ' . $e->getMessage(),
				['app' => 'user_external']
			);
			return false;
		}

		// 2. Get user data

		try {
			$ldap->unbind();
			$ldap->bind($this->user, $this->password);
		}
		catch (BindException $e) {
			\OC::$server->getLogger()->error(
				'LDAP: Failed to bind user ' . $this->user . ': ' . $e->getMessage(),
				['app' => 'user_external']
			);
			return false;
		}

		$raw_search = str_replace('%u', $uid, $this->user_filter);
		$filter = Filters::raw($raw_search);

		$search = Operations::search($filter, 'cn', 'mail', 'displayname', 'uid');

		$paging = $ldap->paging($search, 100);
		$entry = null;

		while ($paging->hasEntries()) {
			$entry = $paging->getEntries()->first();
			break;
		}
		
		if ($entry) {
			$uuid = $entry->mail;
			$this->storeUser($$uuid);
			$this->setDisplayName($uuid, $entry->displayname);
			return $uuid;
		} else {
			\OC::$server->getLogger()->error(
				'LDAP: User not found for '.$raw_search,
				['app' => 'user_external']
			);
			return false;
		}
	}
}
