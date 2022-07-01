<?php
/**
 * Author: oswin
 * Time: 2022/7/1-12:33
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use RuntimeException;

/**
 * Crypto Currency Address Codec Library
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
 *
 */
class AddressCodec
{
    /**
     * returns the Uncompressed DER encoded public key
     *
     * @param  array  $point
     * @return string
     */
    public static function hex(array $point): string
    {
        return '04'.$point['x'].$point['y'];
    }

    /**
     * @param  string  $derPubKey
     * @return array
     */
    public static function point(string $derPubKey): array
    {
        if (strpos($derPubKey, '04') === 0 && strlen($derPubKey) === 130) {
            $x = substr($derPubKey, 2, 64);
            $y = substr($derPubKey, 66, 64);
            return compact('x', 'y');
        }

        if (strlen($derPubKey) === 66 && (strpos($derPubKey, '02') === 0 || strpos($derPubKey, '03') === 0)) {
            return self::decompress($derPubKey);
        }

        throw new RuntimeException('Invalid derPubKey format : '.$derPubKey);
    }


    public static function decompress(string $compressedDerPubKey): array
    {
        if (strlen($compressedDerPubKey) === 66 && (strpos($compressedDerPubKey, '02') === 0 || strpos($compressedDerPubKey, '03') === 0)) {
            $x         = substr($compressedDerPubKey, 2, 64);
            $SECp256k1 = new SECp256k1();
            $a         = $SECp256k1->a;
            $b         = $SECp256k1->b;
            $p         = $SECp256k1->p;
            $y         = PointMathGMP::calculateYWithX($x, $a, $b, $p, substr($compressedDerPubKey, 0, 2));

            return compact('x', 'y');
        }

        if (strlen($compressedDerPubKey) === 130 && strpos($compressedDerPubKey, '04') === 0) {
            return self::point($compressedDerPubKey);
        }

        throw new RuntimeException('Invalid compressedDerPubKey format : '.$compressedDerPubKey);
    }

    /**
     * returns the compressed DER encoded public key.
     *
     * @param  array  $pubKey
     * @return string
     */
    public static function compress(array $pubKey): string
    {
        $gmpStrVal = gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10)));
        if ($gmpStrVal === "0") {
            $compressedDerPubKey = '02'.$pubKey['x'];
        } else {
            $compressedDerPubKey = '03'.$pubKey['x'];
        }

        return $compressedDerPubKey;
    }

    /**
     * @param  string  $derPubKey
     * @return string
     */
    public static function hash(string $derPubKey): string
    {
        $sha256 = hash('sha256', hex2bin($derPubKey));
        return hash('ripemd160', hex2bin($sha256));
    }

    /**
     * returns the Bitcoin address version of the Publick Key
     *
     * @param $hex
     * @param $prefix
     * @return string
     */
    public static function encode(string $hex, string $prefix = "00"): string
    {
        $hex_with_prefix = $prefix.$hex;
        $sha256          = hash('sha256', hex2bin($hex_with_prefix));
        $checksum        = hash('sha256', hex2bin($sha256));
        $address         = $hex_with_prefix.substr($checksum, 0, 8);
        return Base58::Encode($address);
    }
}
