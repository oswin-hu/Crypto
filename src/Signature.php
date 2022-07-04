<?php
/**
 * Author: oswin
 * Time: 2022/7/4-17:31
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use Exception;
use RuntimeException;

/**
 *
 */
class Signature
{
    /***
     * Sign a hash with the private key that was set and returns signatures as an array (R,S)
     *
     * @param $hash
     * @param $k
     * @param  null  $nonce
     * @return array
     * @throws Exception
     */
    public static function getSignatureHashPoints($hash, $k, $nonce = null): array
    {
        $SECp256k1 = new SECp256k1();

        $a = $SECp256k1->a;
        $b = $SECp256k1->b;
        $G = $SECp256k1->G;
        $n = $SECp256k1->n;
        $p = $SECp256k1->p;

        if (empty($k)) {
            throw new RuntimeException('No Private Key was defined');
        }

        if ($nonce === null) {
            $random = random_bytes(256);
            $random .= microtime(true).random_int(100000000000, 1000000000000);
            $nonce  = gmp_strval(gmp_mod(gmp_init(hash('sha256', $random), 16), $n), 16);
        }

        //first part of the signature (R).

        $rPt = PointMathGMP::mulPoint($nonce, $G, $a, $b, $p);
        $R   = gmp_strval($rPt ['x'], 16);

        while (strlen($R) < 64) {
            $R = '0'.$R;
        }

        //second part of the signature (S).
        //S = nonce^-1 (hash + privKey * R) mod p
        $gmp_add = gmp_add(gmp_init($hash, 16), gmp_mul(gmp_init($k, 16), gmp_init($R, 16)));
        $S       = gmp_strval(gmp_mod(gmp_mul(gmp_invert(gmp_init($nonce, 16), $n), $gmp_add), $n), 16);

        if (strlen($S) % 2) {
            $S = '0'.$S;
        }

        if (strlen($R) % 2) {
            $R = '0'.$R;
        }

        return compact('R', 'S');
    }

    /***
     * Sign a hash with the private key that was set and returns a DER encoded signature
     *
     * @param $hash
     * @param $k
     * @param  null  $nonce
     * @return string
     * @throws Exception
     */
    public static function signHash($hash, $k, $nonce = null): string
    {
        $points = self::getSignatureHashPoints($hash, $k, $nonce);

        $signature = '02'.dechex(strlen(hex2bin($points['R']))).$points['R'].'02'.dechex(strlen(hex2bin($points['S']))).$points['S'];
        return '30'.dechex(strlen(hex2bin($signature))).$signature;
    }


    /***
     * extract the public key from the signature and using the recovery flag.
     * see http://crypto.stackexchange.com/a/18106/10927
     * based on https://github.com/brainwallet/brainwallet.github.io/blob/master/js/bitcoinsig.js
     * possible public keys are r−1(sR−zG) and r−1(sR′−zG)
     * Recovery flag rules are :
     * binary number between 28 and 35 inclusive
     * if the flag is > 30 then the address is compressed.
     *
     * @param $flag  (INT)
     * @param $R  (HEX String)
     * @param $S  (HEX String)
     * @param $hash  (HEX String)
     * @return false|string|null
     * @throws Exception
     */
    public static function getPubKeyWithRS($flag, $R, $S, $hash)
    {
        $rtn = false;

        if ($flag >= 27 && $flag < 35) {
            $SECp256k1 = new SECp256k1();

            $a = $SECp256k1->a;
            $b = $SECp256k1->b;
            $G = $SECp256k1->G;
            $n = $SECp256k1->n;
            $p = $SECp256k1->p;

            $isCompressed = false;

            if ($flag >= 31) {
                $isCompressed = true;
                $flag         -= 4;
            }
            $recId = $flag - 27;

            //step 1.1
            $x = gmp_add(gmp_init($R, 16), gmp_mul($n, gmp_div_q(gmp_init($recId, 10), gmp_init(2, 10))));

            //step 1.3
            $y = null;
            if ($flag % 2 === 1) {
                $gmpY = PointMathGMP::calculateYWithX(gmp_strval($x, 16), $a, $b, $p, '02');

            } else {
                $gmpY = PointMathGMP::calculateYWithX(gmp_strval($x, 16), $a, $b, $p, '03');
            }

            if (null !== $gmpY) {
                $y = gmp_init($gmpY, 16);
            }

            if (!is_null($y)) {
                $Rpt = ['x' => $x, 'y' => $y];

                //step 1.6.1
                //calculate r^-1 (S*Rpt - eG)
                $eG   = PointMathGMP::mulPoint($hash, $G, $a, $b, $p);
                $RinV = gmp_strval(gmp_invert(gmp_init($R, 16), $n), 16);

                // Possible issue
                $eG['y'] = gmp_mod(gmp_neg($eG['y']), $p);

                $SR = PointMathGMP::mulPoint($S, $Rpt, $a, $b, $p);

                $sR_plus_eGNeg = PointMathGMP::addPoints($SR, $eG, $a, $p);

                $pubKey = PointMathGMP::mulPoint($RinV, $sR_plus_eGNeg, $a, $b, $p);

                $pubKey['x'] = gmp_strval($pubKey['x'], 16);
                $pubKey['y'] = gmp_strval($pubKey['y'], 16);

                while (strlen($pubKey['x']) < 64) {
                    $pubKey['x'] = '0'.$pubKey['x'];
                }

                while (strlen($pubKey['y']) < 64) {
                    $pubKey['y'] = '0'.$pubKey['y'];
                }

                if ($isCompressed) {
                    $derPubKey = AddressCodec::compress($pubKey);
                } else {
                    $derPubKey = AddressCodec::hex($pubKey);
                }

                $rtn = self::checkSignaturePoints($derPubKey, $R, $S, $hash) ? $derPubKey : null;
            } else {
                $rtn = null;
            }
        }

        return $rtn;
    }

}
