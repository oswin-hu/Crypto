<?php
/**
 * Author: oswin
 * Time: 2022/7/1-15:42
 * Description:
 * Version: v1.0
 */

namespace Test;

use Crypto\PrivateKey;
use Crypto\SECp256k1;

class PointMathGMPTest extends TestCase
{

    public function testMulPoint(): void
    {
        $secp256k1 = new SECp256k1();
        $n = $secp256k1->n;
        print_r($n);

    }
}
