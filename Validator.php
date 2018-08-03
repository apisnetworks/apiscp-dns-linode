<?php declare(strict_types=1);

/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * MIT License
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
 */

namespace Opcenter\Dns\Providers\Linode;

use GuzzleHttp\Exception\RequestException;
use Opcenter\Dns\Contracts\ServiceProvider;
use Opcenter\Service\ConfigurationContext;

class Validator implements ServiceProvider
{
	public function valid(ConfigurationContext $ctx, $var): bool
	{
		return ctype_xdigit($var) && static::keyValid((string)$var);
	}

	public static function keyValid(string $key): bool
	{
		try {
			(new Api($key))->do('GET', 'account');
		} catch (RequestException $e) {
			$response = \json_decode($e->getResponse()->getBody()->getContents(), true);
			$reason = array_get($response, 'errors.0.reason', "Invalid key");
			return error("Linode key failed: %s", $reason);
		}
		return true;
	}
}