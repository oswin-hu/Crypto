<?php
/**
 * Author: oswin
 * Time: 2022/7/4-14:58
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use ErrorException;
use Exception;
use RuntimeException;

/**
 * Object orieted interface to Helpful Point Math Operations
 * Using the BCMATH library
 *
 */
class PointMathBCMATH
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
        $nPt = [];

        // 2*ptY
        $pty2 = bcmul(2, $pt['y']);

        // ( 2*ptY )^-1
        $n_pty2 = self::inverse_mod($pty2, $p);

        // 3 * ptX^2
        $three_x2 = bcmul(3, bcpow($pt['x'], 2));

        // (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = bcmod(bcmul(bcadd($three_x2, $a), $n_pty2), $p);

        // slope^2 - 2 * ptX
        $nPt['x'] = bcmod(bcsub(bcpow($slope, 2), bcmul(2, $pt['x'])), $p);

        // slope * (ptX - nPtx) - ptY
        $nPt['y'] = bcmod(bcsub(bcmul($slope, bcsub($pt['x'], $nPt['x'])), $pt['y']), $p);

        if (bccomp(0, $nPt['y']) === 1) {
            $nPt['y'] = bcadd($p, $nPt['y']);
        }

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
        $nPt = [];
        $gcd = self::bcgcd(bcsub($pt1['x'], $pt2['x']), $p);
        if ($gcd !== '1') {
            throw new RuntimeException('This library doesn\'t yet supports point at infinity.');
        }

        if (bcmod(bccomp($pt1['x'], $pt2['x']), $p) === 0) {
            if (bcmod(bcadd($pt1['y'], $pt2['y']), $p) === 0) {
                throw new RuntimeException('This library doesn\'t yet supports point at infinity.');
            }

            return self::doublePoint($pt1, $a, $p);
        }

        // (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
        $slope = bcmod(bcmul(bcsub($pt2['y'], $pt1['y']), self::inverse_mod(bcsub($pt2['x'], $pt1['x']), $p)), $p);

        // slope^2 - ptX1 - ptX2
        $nPt['x'] = bcmod(bcsub(bcsub(bcpow($slope, 2), $pt1['x']), $pt2['x']), $p);

        // slope * (ptX1 - nPtX) - ptY1
        $nPt['y'] = bcmod(bcsub(bcmul($slope, bcsub($pt1['x'], $nPt['x'])), $pt1['y']), $p);

        if (bccomp(0, $nPt['y']) === 1) {
            $nPt['y'] = bcadd($p, $nPt['y']);
        }

        return $nPt;
    }

    /***
     * Returns inverse mod.
     *
     * @param $a
     * @param $m
     * @return int|string
     * @throws ErrorException
     */
    private static function inverse_mod($a, $m)
    {
        while (bccomp($a, 0) === -1) {
            $a = bcadd($m, $a);
        }
        while (bccomp($m, $a) === -1) {
            $a = bcmod($a, $m);
        }

        $c  = $a;
        $d  = $m;
        $uc = 1;
        $vc = 0;
        $ud = 0;
        $vd = 1;
        while (bccomp($c, 0) !== 0) {
            $temp1 = $c;
            $q     = bcdiv($d, $c, 0);
            $c     = bcmod($d, $c);
            $d     = $temp1;
            $temp2 = $uc;
            $temp3 = $vc;
            $uc    = bcsub($ud, bcmul($q, $uc));
            $vc    = bcsub($vd, bcmul($q, $vc));
            $ud    = $temp2;
            $vd    = $temp3;
        }

        if (bccomp($d, 1) === 0) {
            if (bccomp($ud, 0) === 1) {
                $result = $ud;
            } else {
                $result = bcadd($ud, $m);
            }
        } else {
            throw new ErrorException("ERROR: $a and $m are NOT relatively prime.");
        }
        return $result;
    }


    // The Greatest Common Denominator of two large numbers, using BCMath functions.
    private static function bcgcd($value1, $value2)
    {

        if ($value1 < $value2) // Swap $value1 and $value2
        {
            $temp   = $value1;
            $value1 = $value2;
            $value2 = $temp;
        }

        // We use the Euclid's algorithm
        // for finding the Greatest Common Denominator (GCD)
        $mod = 1;

        while ($mod !== 0) {
            $mod    = bcmod($value1, $value2);
            $value1 = $value2;
            $value2 = $mod;
        }

        return $value1;

    }
}
