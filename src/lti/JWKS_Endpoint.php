<?php
namespace IMSGlobal\LTI;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;
use \Firebase\JWT\JWT;

class JWKS_Endpoint {

    private $keys;

    public function __construct(array $keys) {
        $this->keys = $keys;
    }

    public static function new($keys) {
        return new JWKS_Endpoint($keys);
    }

    public static function from_issuer(Database $database, $issuer) {
        $registration = $database->find_registration_by_issuer($issuer);
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public static function from_registration(LTI_Registration $registration) {
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public function get_public_jwks() {
        $jwks = [];
        foreach ($this->keys as $kid => $private_key) {
            try {
                $key = PublicKeyLoader::load($private_key);
            } catch (NoKeyLoadedException $e) {
                continue;
            }
            if ( !$key instanceof RSA ) {
                continue;
            }
            $public = $key instanceof RSA\PrivateKey ? $key->getPublicKey() : $key;
            $raw = $public->toString('Raw');
            $components = array(
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'e' => JWT::urlsafeB64Encode($raw['e']->toBytes()),
                'n' => JWT::urlsafeB64Encode($raw['n']->toBytes()),
                'kid' => $kid,
            );
            $jwks[] = $components;
        }
        return ['keys' => $jwks];
    }

    public function output_jwks() {
        echo json_encode($this->get_public_jwks());
    }

}