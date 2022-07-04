<?php
/**
 * Author: oswin
 * Time: 2022/7/1-18:35
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use RuntimeException;

/**
 * Object Oriented implimentation to Base58.
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
 */
class Base58
{
    /**
     *  Permutation table used for Base58 encoding and decoding.
     *
     * @param $char
     * @param  bool  $reverse
     * @return int|mixed|string|null
     */
    private static function permutation_lookup($char, bool $reverse = false)
    {
        $number        = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
        $lower         = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
        $table         = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
        $table         = array_merge($number, $table, $lower);


        $reversedTable = $table[$char] ?? null;

        if ($reverse) {
            $rev = [];
            foreach ($table as $key => $element) {
                $rev[$element] = $key;
            }

            $reversedTable =  $rev[$char] ?? null;
        }

        return $reversedTable;
    }

    /**
     * encode a hexadecimal string in Base58.
     *
     * @param  string  $data
     * @param  bool  $littleEndian
     * @return string
     */
    public static function encode(string $data, bool $littleEndian = true): string
    {
        $res        = '';
        $dataIntVal = gmp_init($data, 16);
        while (gmp_cmp($dataIntVal, gmp_init(0, 10)) > 0) {
            $qr         = gmp_div_qr($dataIntVal, gmp_init(58, 10));
            $dataIntVal = $qr[0];
            $reminder   = gmp_strval($qr[1]);
            if (!self::permutation_lookup($reminder)) {
                throw new RuntimeException('Something went wrong during base58 encoding');
            }
            $res .= self::permutation_lookup($reminder);
        }

        //get number of leading zeros
        $leading = '';
        $i       = 0;
        while ($data[$i] === '0') {
            if ($i !== 0 && $i % 2) {
                $leading .= '1';
            }
            $i++;
        }

        return $littleEndian ? strrev($res.$leading):$res.$leading;
    }

    /**
     * Decode a Base58 encoded string and returns it's value as a hexadecimal string
     *
     * @param $encodedData
     * @param  bool  $littleEndian
     * @return string
     */
    public static function decode($encodedData, bool $littleEndian = true): string
    {
        $res    = gmp_init(0, 10);
        $length = strlen($encodedData);
        if ($littleEndian) {
            $encodedData = strrev($encodedData);
        }

        for ($i = $length - 1; $i >= 0; $i--) {
            $res = gmp_add(
                gmp_mul(
                    $res,
                    gmp_init(58, 10)
                ),
                self::permutation_lookup($encodedData[$i], true)
            );
        }

        $res = gmp_strval($res, 16);
        $i   = $length - 1;
        while ($encodedData[$i] === '1') {
            $res = '00'.$res;
            $i--;
        }

        if (strlen($res) % 2 !== 0) {
            $res = '0'.$res;
        }

        return $res;
    }
}
