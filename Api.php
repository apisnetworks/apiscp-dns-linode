<?php declare(strict_types=1);

/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * MIT License
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, July 2018
 */


namespace Opcenter\Dns\Providers\Linode;

use GuzzleHttp\Psr7\Response;

class Api {
	protected const ENDPOINT = 'https://api.linode.com/v4/';
	/**
	 * @var \GuzzleHttp\Client
	 */
	protected $client;
	/**
	 * @var string
	 */
	protected $key;

	/**
	 * @var Response
	 */
	protected $lastResponse;

	/**
	 * Api constructor.
	 *
	 * @param string $key API key
	 */
	public function __construct(string $key)
	{
		$this->key = $key;
		$this->client = new \GuzzleHttp\Client([
			'base_uri' => static::ENDPOINT,
		]);
	}

	public function do(string $method, string $endpoint, array $params = null): array
	{
		$method = strtoupper($method);
		if (!\in_array($method, ['GET', 'POST', 'PUT', 'DELETE'])) {
			error("Unknown method `%s'", $method);
			return [];
		}
		if ($endpoint[0] === '/') {
			warn("Stripping `/' from endpoint `%s'", $endpoint);
			$endpoint = ltrim($endpoint, '/');
		}
		$this->lastResponse = $this->client->request($method, $endpoint, [
			'headers' => [
				'User-Agent' => PANEL_BRAND . " " . APNSCP_VERSION,
				'Accept' => 'application/json',
				'Authorization' => 'Bearer ' . $this->key
			],
			'json' => $params
		]);
		return \json_decode($this->lastResponse->getBody()->getContents(), true) ?? [];
	}

	public function getResponse(): Response
	{
		return $this->lastResponse;
	}
}