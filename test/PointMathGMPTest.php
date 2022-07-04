<?php
/**
 * Author: oswin
 * Time: 2022/7/1-15:42
 * Description:
 * Version: v1.0
 */

namespace Test;

class PointMathGMPTest extends TestCase
{

    public function testMulPoint(): void
    {
        $at = gmp_add("10.01", '10.02');
        print_r($at);
    }
}
