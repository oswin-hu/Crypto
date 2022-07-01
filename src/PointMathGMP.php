<?php
/**
 * Author: oswin
 * Time: 2022/7/1-14:13
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use Exception;
use RuntimeException;

/**
 * Object orieted interface to Helpful Point Math Operations
 * Using the GMP library
 *
 */
class PointMathGMP
{

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param  array  $pt
     * @param $a
     * @param $p
     * @return array Point
     * @throws Exception
     */
    public static function doublePoint(array $pt, $a, $p): array
    {
        $gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p));
        if ($gcd !== '1') {
            throw new RuntimeException('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }

        $gmpInvert = gmp_invert(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p);
        $gmpAdd    = gmp_add(gmp_mul(gmp_init(3, 10), gmp_pow($pt['x'], 2)), $a);

        $slope = gmp_mod(gmp_mul($gmpInvert, $gmpAdd), $p);

        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $pt['x']), $pt['x']), $p);
        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($pt['x'], $nPt['x'])), $pt['y']), $p);

        return $nPt;
    }

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param  array  $pt1
     * @param  array  $pt2
     * @param $a
     * @param $p
     * @return array Point
     * @throws Exception
     */
    public static function addPoints(array $pt1, array $pt2, $a, $p): array
    {
        if (gmp_cmp($pt1['x'], $pt2['x']) === 0 && gmp_cmp($pt1['y'], $pt2['y']) === 0) //if identical
        {
            return self::doublePoint($pt1, $a, $p);
        }

        $gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
        if ($gcd !== '1') {
            throw new RuntimeException('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }


        $slope = gmp_mod(gmp_mul(gmp_sub($pt1['y'], $pt2['y']), gmp_invert(gmp_sub($pt1['x'], $pt2['x']), $p)), $p);

        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $pt1['x']), $pt2['x']), $p);
        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($pt1['x'], $nPt['x'])), $pt1['y']), $p);

        return $nPt;
    }

    /***
     * Computes the result of a point multiplication and returns the resulting point as an Array.
     *
     * @param  String Hex $k
     * @param  array  $pG  (GMP, GMP)
     * @param $base  (INT)
     * @return array Point (GMP, GMP)
     * @throws Exception
     */
    public static function mulPoint($k, array $pG, $a, $b, $p, $base = null): array
    {
        //in order to calculate k*G
        if ($base === 16 || $base === null || is_resource($base)) {
            $k = gmp_init($k, 16);
        }
        if ($base === 10) {
            $k = gmp_init($k, 10);
        }
        $kBin = gmp_strval($k, 2);

        $lastPoint = $pG;
        $iMax      = strlen($kBin);
        for ($i = 1; $i < $iMax; $i++) {
            if ((int)$kBin[$i] === 1) {
                $dPt       = self::doublePoint($lastPoint, $a, $p);
                $lastPoint = self::addPoints($dPt, $pG, $a, $p);
            } else {
                $lastPoint = self::doublePoint($lastPoint, $a, $p);
            }
        }
        if (!self::validatePoint(gmp_strval($lastPoint['x'], 16), gmp_strval($lastPoint['y'], 16), $a, $b, $p)) {
            throw new RuntimeException('The resulting point is not on the curve.');
        }
        return $lastPoint;
    }

    /***
     * Calculates the square root of $a mod p and returns the 2 solutions as an array.
     *
     * @param $a
     * @param $p
     * @return array|null
     */
    public static function sqrt($a, $p): ?array
    {
        if (gmp_legendre($a, $p) !== 1) {
            //no result
            return null;
        }

        if (gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) === "3") {
            $sqrt1 = gmp_powm($a, gmp_div_q(gmp_add($p, gmp_init(1, 10)), gmp_init(4, 10)), $p);
            // there are always 2 results for a square root
            // In an infinite number field you have -2^2 = 2^2 = 4
            // In a finite number field you have a^2 = (p-a)^2
            $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
            return array($sqrt1, $sqrt2);
        }

        throw new RuntimeException('P % 4 != 3 , this isn\'t supported yet.');
    }

    /***
     * Calculate the Y coordinates for a given X coordinate.
     *
     * @param $x
     * @param $a
     * @param $b
     * @param $p
     * @param  null  $derEvenOrOddCode
     * @return array|null|String
     */
    public static function calculateYWithX($x, $a, $b, $p, $derEvenOrOddCode = null): ?array
    {
        $resY = nulll;

        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(gmp_add(gmp_add(gmp_powm($x, gmp_init(3, 10), $p), gmp_mul($a, $x)), $b), $p);

        $y = self::sqrt($y2, $p);
        if (!empty($y)) {
            switch ($derEvenOrOddCode) {
                case '02':
                    if (!gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[0], 16);
                    }

                    if (!gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[1], 16);
                    }

                    if (!empty($resY)) {
                        while (strlen($resY) < 64) {
                            $resY = '0'.$resY;
                        }
                    }
                    break;
                case '03':
                    if (gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[0], 16);
                    }

                    if (gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[1], 16);
                    }

                    if (!empty($resY)) {
                        while (strlen($resY) < 64) {
                            $resY = '0'.$resY;
                        }
                    }
                    break;
                default:
                    if (!empty($derEvenOrOddCode)) {
                        $resY = $y;
                    }
            }

        }
        return $resY;
    }

    /**
     * Returns true if the point is on the curve and false if it isn't.
     *
     * @param $x
     * @param $y
     * @param $a
     * @param $b
     * @param $p
     * @return bool
     */
    public static function validatePoint($x, $y, $a, $b, $p): bool
    {
        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(gmp_add(gmp_add(gmp_powm($x, gmp_init(3, 10), $p), gmp_mul($a, $x)), $b), $p
        );
        $y  = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

        return gmp_cmp($y2, $y) === 0;
    }

}
