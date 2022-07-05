<?php
/**
 * Author: oswin
 * Time: 2022/7/4-15:56
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use Exception;
use RuntimeException;

/**
 * Private Key
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
 *
 */
class PrivateKey
{

    public string $k;

    public string $n;

    public $a;
    public $b;
    public $p;
    public array $G;

    /**
     * @param $private_key
     * @throws Exception
     */
    public function __construct($private_key = null)
    {
        $SECp256k1 = new SECp256k1();
        $this->n   = $SECp256k1->n;
        $this->G   = $SECp256k1->G;
        $this->a   = $SECp256k1->a;
        $this->b   = $SECp256k1->b;
        $this->p   = $SECp256k1->p;
        if (empty($private_key)) {
            $this->generateRandomPrivateKey();
        } else {
            $this->setPrivateKey($private_key);
        }

    }


    /***
     * Generate a new random private key.
     * The extra parameter can be some random data typed down by the user or mouse movements to add randomness.
     *
     * @param  string  $extra
     * @throws Exception
     */
    public function generateRandomPrivateKey(string $extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d'): void
    {
        //private key has to be passed as an hexadecimal number
        do { //generate a new random private key until to find one that is valid
            $bytes   = random_bytes(256);
            $hex     = bin2hex($bytes);
            $random  = $hex.microtime(true).random_int(100000000000, 1000000000000).$extra;
            $this->k = hash('sha256', $random);
        } while (gmp_cmp(gmp_init($this->k, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1);
    }

    /***
     * return the private key.
     *
     * @return string Hex
     */
    public function getPrivateKey(): string
    {
        return $this->k;
    }

    /***
     * set a private key.
     *
     * @param  string Hex $k
     * @throws Exception
     */
    public function setPrivateKey(string $k): void
    {
        //private key has to be passed as an hexadecimal number
        if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1) {
            throw new RuntimeException('Private Key is not in the 1,n-1 range');
        }
        $this->k = $k;
    }

    /***
     * returns the X and Y point coordinates of the public key.
     *
     * @return array Point
     * @throws Exception
     */
    public function getPubKeyPoints(): array
    {

        if (!isset($this->k)) {
            throw new RuntimeException('No Private Key was defined');
        }

        $pubKey = PointMathGMP::mulPoint($this->k, ['x' => $this->G['x'], 'y' => $this->G['y']], $this->a, $this->b, $this->p);

        $pubKey['x'] = gmp_strval($pubKey['x'], 16);
        $pubKey['y'] = gmp_strval($pubKey['y'], 16);

        while (strlen($pubKey['x']) < 64) {
            $pubKey['x'] = '0'.$pubKey['x'];
        }

        while (strlen($pubKey['y']) < 64) {
            $pubKey['y'] = '0'.$pubKey['y'];
        }

        return $pubKey;
    }

}
