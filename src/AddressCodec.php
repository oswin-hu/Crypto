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
            $a = $SECp256k1->a;
            $b = $SECp256k1->b;
            $p = $SECp256k1->p;


        }
    }
}
