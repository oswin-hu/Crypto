<?php
/**
 * Author: oswin
 * Time: 2022/7/4-14:17
 * Description:
 * Version: v1.0
 */

namespace Crypto;

/**
 * Crypto Currency Address Validation Library
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
 */
class AddressValidation
{
    /***
     * Tests if the address is valid or not.
     *
     * @param  String Base58 $address
     * @return bool
     */
    public static function validateAddress(string $address): bool
    {
        $validate = false;
        $address  = hex2bin(Base58::decode($address));
        if (strlen($address) === 25) {
            $checksum   = substr($address, 21, 4);
            $rawAddress = substr($address, 0, 21);
            $sha256     = hash('sha256', $rawAddress);
            $sha256     = hash('sha256', hex2bin($sha256));

            $validate = strpos(hex2bin($sha256), $checksum) === 0;
        }

        return $validate;
    }


    /***
     * Tests if the Wif key (Wallet Import Format) is valid or not.
     *
     * @param  String Base58 $wif
     * @return bool
     */
    public static function validateWifKey(string $wif): ?bool
    {
        $key          = Base58::decode($wif, false);
        $length       = strlen($key);
        $firstSha256  = hash('sha256', hex2bin(substr($key, 0, $length - 8)));
        $secondSha256 = hash('sha256', hex2bin($firstSha256));
        return strpos($secondSha256, substr($key, $length - 8, 8)) === 0;
    }
}
