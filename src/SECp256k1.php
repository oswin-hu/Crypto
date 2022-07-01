<?php
/**
 * Author: oswin
 * Time: 2022/7/1-14:02
 * Description:
 * Version: v1.0
 */

namespace Crypto;

/**
 * The SECp256k1 curve
 * Fundamental ECC Function for Bitcoin/Zetacoin compatable Crypto Currency
 */
class SECp256k1
{
    public $a;
    public $b;
    public $p;
    public $n;
    public array $G;

    public function __construct()
    {
        $x       = gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240');
        $y       = gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424');
        $this->a = gmp_init('0', 10);
        $this->b = gmp_init('7', 10);
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
        $this->G = compact('x', 'y');

    }
}
