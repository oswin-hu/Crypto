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


    // Same as Below but accepts HEX strings
    public static function recoverPublicKey_hEX($flag, $R, $S, $hash): array
    {
        return self::recoverPublicKey(gmp_init($R, 16), gmp_init($S, 16), gmp_init($hash, 16), $flag);
    }


    /**
     * $R, $S, and $hash are GMP
     *
     * $recoveryFlags is INT
     * @param $R
     * @param $S
     * @param $hash
     * @param $recoveryFlags
     * @return array
     * @throws Exception
     */
    public static function recoverPublicKey($R, $S, $hash, $recoveryFlags): array
    {
        $SECp256k1 = new SECp256k1();

        $a = $SECp256k1->a;
        $b = $SECp256k1->b;
        $G = $SECp256k1->G;
        $n = $SECp256k1->n;
        $p = $SECp256k1->p;

        $isYEven     = ($recoveryFlags & 1) !== 0;
        $isSecondKey = ($recoveryFlags & 2) !== 0;

        // PointMathGMP::mulPoint wants HEX String
        $e = gmp_strval($hash, 16);
        $s = gmp_strval($S, 16);

        // Precalculate (p + 1) / 4 where p is the field order
        // $p_over_four is GMP
        static $p_over_four; // XXX just assuming only one curve/prime will be used
        if (!$p_over_four) {
            $p_over_four = gmp_div(gmp_add($p, 1), 4);
        }

        // 1.1 Compute x
        // $x is GMP
        if (!$isSecondKey) {
            $x = $R;
        } else {
            $x = gmp_add($R, $n);
        }

        // 1.3 Convert x to point
        // $alpha is GMP
        $alpha = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($a, $x)), $b), $p);
        // $beta is DEC String (INT)
        $beta = gmp_strval(gmp_powm($alpha, $p_over_four, $p));

        // If beta is even, but y isn't or vice versa, then convert it,
        // otherwise we're done and y == beta.
        if (PointMathGMP::isEvenNumber($beta) === $isYEven) {
            // gmp_sub function will convert the DEC String "$beta" into a GMP
            // $y is a GMP
            $y = gmp_sub($p, $beta);
        } else {
            // $y is a GMP
            $y = gmp_init($beta);
        }

        // 1.4 Check that nR is at infinity (implicitly done in construtor) -- Not reallly
        // $Rpt is Array(GMP, GMP)
        $Rpt = array('x' => $x, 'y' => $y);

        // 1.6.1 Compute a candidate public key Q = r^-1 (sR - eG)
        // $rInv is a HEX String
        $rInv = gmp_strval(gmp_invert($R, $n), 16);

        // $eGNeg is Array (GMP, GMP)
        $eGNeg = PointMathGMP::negatePoint(PointMathGMP::mulPoint($e, $G, $a, $b, $p));

        $sR = PointMathGMP::mulPoint($s, $Rpt, $a, $b, $p);

        $sR_plus_eGNeg = PointMathGMP::addPoints($sR, $eGNeg, $a, $p);

        // $Q is Array (GMP, GMP)
        $Q = PointMathGMP::mulPoint($rInv, $sR_plus_eGNeg, $a, $b, $p);

        // Q is the derrived public key
        // $pubkey is Array (HEX String, HEX String)
        // Ensure it's always 64 HEX Charaters
        $pubKey['x'] = str_pad(gmp_strval($Q['x'], 16), 64, 0, STR_PAD_LEFT);
        $pubKey['y'] = str_pad(gmp_strval($Q['y'], 16), 64, 0, STR_PAD_LEFT);

        return $pubKey;
    }


    /***
     * Check signature with public key R & S values of the signature and the message hash.
     *
     * @param $pubKey
     * @param $R
     * @param $S
     * @param $hash
     * @return bool
     * @throws Exception
     */
    public static function checkSignaturePoints($pubKey, $R, $S, $hash): ?bool
    {
        $SECp256k1 = new SECp256k1();

        $a = $SECp256k1->a;
        $b = $SECp256k1->b;
        $G = $SECp256k1->G;
        $n = $SECp256k1->n;
        $p = $SECp256k1->p;

        $pubKeyPts = AddressCodec::Decompress($pubKey);

        // S^-1* hash * G + S^-1 * R * Qa

        // S^-1* hash
        $exp1 = gmp_strval(gmp_mul(gmp_invert(gmp_init($S, 16), $n), gmp_init($hash, 16)), 16);

        // S^-1* hash * G
        $exp1Pt = PointMathGMP::mulPoint($exp1, $G, $a, $b, $p);


        // S^-1 * R
        $exp2 = gmp_strval(gmp_mul(gmp_invert(gmp_init($S, 16), $n), gmp_init($R, 16)), 16);
        // S^-1 * R * Qa

        $pubKeyPts['x'] = gmp_init($pubKeyPts['x'], 16);
        $pubKeyPts['y'] = gmp_init($pubKeyPts['y'], 16);

        $exp2Pt      = PointMathGMP::mulPoint($exp2, $pubKeyPts, $a, $b, $p);
        $resultingPt = PointMathGMP::addPoints($exp1Pt, $exp2Pt, $a, $p);

        $xRes = gmp_strval($resultingPt['x'], 16);

        while (strlen($xRes) < 64) {
            $xRes = '0'.$xRes;
        }

        return $xRes === $R;
    }

    /***
     * checkSignaturePoints wrapper for DER signatures
     *
     * @param $pubKey
     * @param $signature
     * @param $hash
     * @return bool
     * @throws Exception
     */
    public static function checkDerSignature($pubKey, $signature, $hash): ?bool
    {
        $rtn = false;

        $signature = hex2bin($signature);

        if (bin2hex($signature[0]) === '30') {
            $RLength = hexdec(bin2hex($signature[3]));
            $R       = bin2hex(substr($signature, 4, $RLength));

            $SLength = hexdec(bin2hex($signature[$RLength + 5]));
            $S       = bin2hex(substr($signature, $RLength + 6, $SLength));

            $rtn = self::checkSignaturePoints($pubKey, $R, $S, $hash);
        }

        return $rtn;
    }

}
