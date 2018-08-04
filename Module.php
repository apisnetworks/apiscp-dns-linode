<?php declare(strict_types=1);

/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * MIT License
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
 */

	namespace Opcenter\Dns\Providers\Linode;

	use GuzzleHttp\Exception\ClientException;
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Dns\Record;

	class Module extends \Dns_Module implements ProviderInterface
	{
		use \NamespaceUtilitiesTrait;

		const DNS_TTL = 1800;

		protected $metaCache = [];
		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = false;
		protected static $permitted_records = [
			'A',
			'AAAA',
			'CAA',
			'CNAME',
			'MX',
			'NS',
			'SRV',
			'TXT',
			'ANY',
		];
		// @var array API credentials
		private $key;

		public function __construct()
		{
			parent::__construct();
			$this->key = $this->get_service_value('dns', 'key', DNS_PROVIDER_KEY);
		}

		/**
		 * Get raw zone data
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr($domain): ?string
		{
			// @todo hold records in cache and synthesize AXFR
			$client = $this->makeApi();

			try {
				if (!$domainid = $this->getZoneId($domain)) {
					return null;
				}
				$records = $client->do('GET', "domains/${domainid}/records");
				if (empty($records['data'])) {
					return null;
				}
				$soa = array_get($this->get_records_external('', 'soa', $domain,
					$this->get_hosting_nameservers($domain)), 0, []);

				$ttldef = (int)array_get(preg_split('/\s+/', $soa['parameter'] ?? ''), 6, static::DNS_TTL);
				$preamble = [];
				if ($soa) {
					$preamble = [
						"${domain}.\t${ttldef}\tIN\tSOA\t${soa['parameter']}",
					];
				}
				foreach ($this->get_hosting_nameservers($domain) as $ns) {
					$preamble[] = "${domain}.\t${ttldef}\tIN\tNS\t${ns}.";
				}

			} catch (ClientException $e) {
				if ($e->getResponse()->getStatusCode() === 401) {
					// zone doesn't exist
					return null;
				}
				error("Failed to transfer DNS records from Linode - try again later. Response code: %d", $e->getResponse()->getStatusCode());
				return null;
			}
			$this->zoneCache[$domain] = [];
			foreach ($records['data'] as $r) {
				switch ($r['type']) {
					case 'CAA':
						$parameter = $r['tag'] . " " . $r['flags'] . " " . $r['target'];
						break;
					case 'SRV':
						$parameter = $r['priority'] . " " . $r['weight'] . " " . $r['port'] . " " . $r['target'];
						break;
					case 'MX':
						$parameter = $r['priority'] . " " . $r['target'];
						break;
					default:
						$parameter = $r['target'];
				}
				$hostname = ltrim($r['name'] . "." . $domain, '.') . '.';
				$preamble[] = $hostname . "\t" . $r['ttl_sec'] . "\tIN\t" .
					$r['type'] . "\t" . $parameter;

				$this->addCache(new Record($domain,
					[
						'name'      => $r['name'],
						'rr'        => $r['type'],
						'ttl'       => $r['ttl'] ?? static::DNS_TTL,
						'parameter' => $parameter,
						'meta'      => [
							'id' => $r['id']
						]
					]
				));
			}
			$axfrrec = implode("\n", $preamble);
			$this->zoneCache[$domain]['text'] = $axfrrec;
			return $axfrrec;
		}

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, Record $old, Record $new): bool
		{
			if (!$this->canonicalizeRecord($zone, $old['name'], $old['rr'], $old['parameter'], $old['ttl'])) {
				return false;
			}
			if (!$this->getRecordId($old)) {
				return error("failed to find record ID in Linode zone `%s' - does `%s' (rr: `%s', parameter: `%s') exist?",
					$zone, $old['name'], $old['rr'], $old['parameter']);
			}
			if (!$this->canonicalizeRecord($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'])) {
				return false;
			}
			$api = $this->makeApi();
			try {
				$merged = clone $old;
				$new = $merged->merge($new);
				$id = $this->getRecordId($old);
				$domainid = $this->getZoneId($zone);
				$api->do('PUT', "domains/${domainid}/records/${id}", $this->formatRecord($new));
			} catch (ClientException $e) {
				return error("Failed to update record `%s' on zone `%s' (old - rr: `%s', param: `%s'; new - rr: `%s', param: `%s'): %s",
					$old['name'],
					$zone,
					$old['rr'],
					$old['parameter'], $new['name'] ?? $old['name'], $new['parameter'] ?? $old['parameter'],
					$this->renderMessage($e)
				);
			}
			array_forget($this->zoneCache[$old->getZone()], $this->getCacheKey($old));
			$this->addCache($new);

			return true;
		}

		/**
		 * Add a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		public function add_record(
			string $zone,
			string $subdomain,
			string $rr,
			string $param,
			int $ttl = self::DNS_TTL
		): bool {
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			$api = $this->makeApi();
			$record = new Record($zone, [
				'name'      => $subdomain,
				'rr'        => $rr,
				'parameter' => $param,
				'ttl'       => $ttl
			]);

			try {
				$zoneid = $this->getZoneId($zone);
				$ret = $api->do('POST', "domains/${zoneid}/records", $this->formatRecord($record));
				$this->addCache($record);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to create record `%s' type %s: %s", $fqdn, $rr, $this->renderMessage($e));
			}

			return (bool)$ret;
		}

		/**
		 * Extract JSON message if present
		 *
		 * @param ClientException $e
		 * @return string
		 */
		private function renderMessage(ClientException $e): string
		{

			$body = \Error_Reporter::silence(function () use ($e) {
				return \json_decode($e->getResponse()->getBody()->getContents(), true);
			});
			if (!$body || !($reason = array_get($body, 'errors.0.reason'))) {
				return $e->getMessage();
			}
			return $reason;
		}

		/**
		 * Remove a DNS record
		 *
		 * @param string      $zone
		 * @param string      $subdomain
		 * @param string      $rr
		 * @param string|null $param
		 * @return bool
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = null): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			$api = $this->makeApi();

			$id = $this->getRecordId($r = new Record($zone,
				['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]));
			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Record `%s' (rr: `%s', param: `%s')  does not exist", $fqdn, $rr, $param);
			}

			try {
				$domainid = $this->getZoneId($zone);
				$api->do('DELETE', "domains/${domainid}/records/${id}");
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to delete record `%s' type %s", $fqdn, $rr);
			}
			array_forget($this->zoneCache[$r->getZone()], $this->getCacheKey($r));
			return $api->getResponse()->getStatusCode() === 200;
		}

		/**
		 * Get hosting nameservers
		 *
		 * @param string|null $domain
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			return ['ns1.linode.com', 'ns2.linode.com', 'ns3.linode.com', 'ns4.linode.com', 'ns5.linode.com'];
		}

		/**
		 * Add DNS zone to service
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool
		{
			/**
			 * @var Zones $api
			 */
			$api = $this->makeApi();
			try {
				$resp = $api->do('POST', 'domains', [
					'domain' => $domain,
					'type' => 'master',
					'soa_email' => "hostmaster@${domain}"
				]);
			} catch (ClientException $e) {
				return error("Failed to add zone `%s', error: %s", $domain, $this->renderMessage($e));
			}
			return true;
		}

		public function add_zone(string $domain, string $ip): bool
		{
			if (!parent::add_zone($domain, $ip)) {
				return false;
			}
			for ($i = 0; $i < 10; $i++) {
				if (null !== $this->getZoneId($domain)) {
					return true;
				}
				sleep(1);
			}
			return warn("Zone `%s' added but Linode not reporting authoritative yet", $domain);
		}


		/**
		 * Remove DNS zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			$api = $this->makeApi();
			try {
				$domainid = $this->getZoneId($domain);
				if (!$domainid) {
					return warn("Domain ID not found - `%s' already removed?", $domain);
				}
				$api->do('DELETE', "domains/${domainid}");
			} catch (ClientException $e) {
				return error("Failed to remove zone `%s', error: %s", $domain, $this->renderMessage($e));
			}

			return true;
		}

		/**
		 * Get zone meta information
		 *
		 * @param string $domain
		 * @param string $key
		 * @return mixed|null
		 */
		private function getZoneMeta(string $domain, string $key = null)
		{
			if (!isset($this->metaCache[$domain])) {
				$this->populateZoneMetaCache();
			}
			if (!$key) {
				return $this->metaCache[$domain] ?? null;
			}
			return $this->metaCache[$domain][$key] ?? null;
		}

		/**
		 * Populate zone cache
		 *
		 * @param int $pagenr
		 * @return mixed
		 */
		protected function populateZoneMetaCache($pagenr = 1)
		{
			// @todo support > 100 domains
			$api = $this->makeApi();
			$raw = array_map(function ($zone) {
				return $zone;
			}, $api->do('GET', 'domains', ['page' => $pagenr]));
			$this->metaCache = array_merge($this->metaCache, array_combine(array_column($raw['data'], 'domain'), $raw['data']));
			$pagecnt = $raw['pages'];
			if ($pagenr < $pagecnt && $raw['data']) {
				return $this->populateZoneMetaCache(++$pagenr);
			}
		}

		/**
		 * Get internal Linode zone ID
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function getZoneId(string $domain): ?string
		{
			return (string)$this->getZoneMeta($domain, 'id');
		}

		/**
		 * CNAME cannot be present in root
		 *
		 * @return bool
		 */
		protected function hasCnameApexRestriction(): bool
		{
			return true;
		}

		/**
		 * Create a Linode API client
		 *
		 * @return Api
		 */
		private function makeApi(): Api
		{
			return new Api($this->key);
		}

		/**
		 * Format a Linode record from apnscp
		 *
		 * @param Record $r
		 * @return array
		 */
		protected function formatRecord(Record $r): ?array
		{
			$args = [
				'type' => strtoupper($r['rr']),
				'ttl_sec'  => $r['ttl'] ?? static::DNS_TTL
			];
			switch ($args['type']) {
				case 'A':
				case 'AAAA':
				case 'CNAME':
				case 'TXT':
				case 'NS':
					return $args + ['name' => $r['name'], 'target' => $r['parameter']];
				case 'MX':
					return $args + ['name'     => $r['name'],
					                'priority' => (int)$r->getMeta('priority'),
					                'target'     => $r->getMeta('data')
						];
				case 'SRV':
					return $args + [
							'name'     => $r->getMeta('name'),
							'protocol' => $r->getMeta('protocol'),
							'service'  => $r->getMeta('service'),
							'priority' => $r->getMeta('priority'),
							'weight'   => $r->getMeta('weight'),
							'port'     => $r->getMeta('port'),
							'data'     => $r->getMeta('data')
						];
				case 'CAA':
					return $args + [
							'tag'   => $r->getMeta('tag'),
							'target'  => $r->getMeta('flags') . ' ' . $r->getMeta('data')
						];
				default:
					fatal("Unsupported DNS RR type `%s'", $r['type']);
			}
		}
	}
